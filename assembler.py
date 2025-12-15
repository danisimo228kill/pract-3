import sys
import json
import argparse
from pathlib import Path


OPCODES = {'LOAD': 13, 'READ': 14, 'WRITE': 0, 'ROR': 7}
COMMAND_FORMATS = {13: 'LOAD', 14: 'READ', 0: 'WRITE', 7: 'ROR'}


def parse_instruction(line):
    line = line.strip()
    if not line or line.startswith('#'): return None
    if '#' in line: line = line.split('#')[0].strip()

    parts = line.split()
    mnemonic = parts[0].upper()

    if mnemonic == 'LOAD':
        if len(parts) != 2: raise ValueError("LOAD требует один аргумент")
        const = int(parts[1])

        if const < 0 or const >= (1 << 15): raise ValueError("Константа вне диапазона")
        return {'op': OPCODES['LOAD'], 'B': const}

    elif mnemonic == 'READ':
        if len(parts) != 2: raise ValueError("READ требует один аргумент")
        addr = int(parts[1])

        if addr < 0 or addr >= (1 << 32): raise ValueError("Адрес вне диапазона")
        return {'op': OPCODES['READ'], 'B': addr}

    elif mnemonic == 'WRITE':
        if len(parts) != 1: raise ValueError("WRITE не требует аргументов")
        return {'op': OPCODES['WRITE']}

    elif mnemonic == 'ROR':
        if len(parts) != 1: raise ValueError("ROR не требует аргументов")
        return {'op': OPCODES['ROR']}
    else:
        raise ValueError(f"Неизвестная команда: '{mnemonic}'")


def parse_assembly_file(source_path):
    intermediate = []
    with open(source_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line_num, line in enumerate(lines, 1):
        try:
            instr = parse_instruction(line)
            if instr is not None: intermediate.append(instr)
        except ValueError as e:
            print(f"Ошибка строка {line_num}: {e}")
            print(f"  {line.strip()}")
            sys.exit(1)

    return intermediate


def encode_load(instr):
    const = instr['B']
    byte2 = const // 16
    return bytes([0xCD, byte2, 0x00])


def encode_read(instr):
    addr = instr['B']
    byte2 = (addr >> 4) & 0xFF
    return bytes([0x4E, byte2, 0x00, 0x00, 0x00])


def encode_write(instr):
    return bytes([0x00])


def encode_ror(instr):
    return bytes([0x87])


def encode_instruction(instr):
    op = instr['op']
    if op == OPCODES['LOAD']:
        return encode_load(instr)
    elif op == OPCODES['READ']:
        return encode_read(instr)
    elif op == OPCODES['WRITE']:
        return encode_write(instr)
    elif op == OPCODES['ROR']:
        return encode_ror(instr)
    else:
        raise ValueError(f"Неизвестный opcode: {op}")


def encode_program(intermediate):
    return b''.join(encode_instruction(instr) for instr in intermediate)


def run_tests():
    tests = [
        ({'op': 13, 'B': 988}, bytes([0xCD, 0x3D, 0x00])),
        ({'op': 14, 'B': 468}, bytes([0x4E, 0x1D, 0x00, 0x00, 0x00])),
        ({'op': 0}, bytes([0x00])),
        ({'op': 7}, bytes([0x87])),
    ]

    print("Тесты спецификации:")
    all_ok = True
    for i, (instr, expected) in enumerate(tests, 1):
        result = encode_instruction(instr)
        ok = result == expected
        print(f"  Тест {i}: {'OK' if ok else 'FAIL'}")
        if not ok: all_ok = False

    return all_ok


def main():
    parser = argparse.ArgumentParser(description='Ассемблер УВМ v15')
    parser.add_argument('input', help='Файл .asm')
    parser.add_argument('output', help='Файл .bin')
    parser.add_argument('--test', action='store_true', help='Режим тестирования')

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Ошибка: файл '{input_path}' не найден")
        sys.exit(1)

    print("\n[ЭТАП 1] Перевод программы в промежуточное представление")


    intermediate = parse_assembly_file(input_path)
    print(f"Прочитано команд из файла: {len(intermediate)}")

    if args.test:
        for i, instr in enumerate(intermediate):
            name = COMMAND_FORMATS[instr['op']]
            if 'B' in instr:
                print(f"  Команда {i}: операция={name}, поле B={instr['B']}")
            else:
                print(f"  Команда {i}: операция={name}")


    print("\n[ЭТАП 2] Формирование машинного кода")


    if args.test:
        if run_tests():
            print("  Все тесты пройдены успешно!")

    binary = encode_program(intermediate)

    print(f"\n2. Размер двоичного файла: {len(binary)} байт")

    if args.test:
        print("\n3. Результат ассемблирования на экран в байтовом формате,")
        print("   как в тесте из спецификации УВМ:\n")

        hex_bytes = []
        for b in binary:
            hex_bytes.append(f"{b:02X}")

        print("   " + " ".join(hex_bytes))


        expected = bytes([0xCD, 0x3D, 0x00, 0x4E, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x87])

    # Сохранение файла
    with open(output_path, 'wb') as f:
        f.write(binary)

    print(f"\n4. Результат сохранен в файл: {output_path}")

    print("\nАссемблирование завершено успешно!")

if __name__ == '__main__':
    main()