import sys
import json
import argparse
from pathlib import Path

OPCODES = {'LOAD': 13, 'READ': 14, 'WRITE': 0, 'ROR': 7}
COMMAND_FORMATS = {13: 'LOAD', 14: 'READ', 0: 'WRITE', 7: 'ROR'}


def parse_instruction_from_json(instr_dict):
    mnemonic = instr_dict.get("mnemonic", "").upper()

    if mnemonic == 'LOAD':
        if "operand" not in instr_dict:
            raise ValueError("LOAD требует operand в JSON")
        const = int(instr_dict["operand"])
        if const < 0 or const >= (1 << 15):
            raise ValueError("Константа вне диапазона")
        return {'op': OPCODES['LOAD'], 'B': const}

    elif mnemonic == 'READ':
        if "operand" not in instr_dict:
            raise ValueError("READ требует operand в JSON")
        addr = int(instr_dict["operand"])
        if addr < 0 or addr >= (1 << 32):
            raise ValueError("Адрес вне диапазона")
        return {'op': OPCODES['READ'], 'B': addr}

    elif mnemonic == 'WRITE':
        return {'op': OPCODES['WRITE']}

    elif mnemonic == 'ROR':
        return {'op': OPCODES['ROR']}
    else:
        raise ValueError(f"Неизвестная команда: '{mnemonic}'")


def parse_json_file(json_path):
    intermediate = []

    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            program_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Ошибка парсинга JSON: {e}")
        sys.exit(1)

    # Проверяем структуру JSON
    if not isinstance(program_data, list):
        print("Ошибка: JSON должен содержать массив инструкций")
        sys.exit(1)

    for line_num, instr_dict in enumerate(program_data, 1):
        try:
            instr = parse_instruction_from_json(instr_dict)
            if instr is not None:
                intermediate.append(instr)
        except ValueError as e:
            print(f"Ошибка в инструкции {line_num}: {e}")
            print(f"  JSON: {instr_dict}")
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
        if not ok:
            all_ok = False
            print(f"    Ожидалось: {expected.hex()}")
            print(f"    Получено:  {result.hex()}")

    return all_ok


def create_test_json_file():
    """Создание тестового JSON файла с инструкциями из спецификации"""
    test_program = [
        {"mnemonic": "LOAD", "operand": 988},
        {"mnemonic": "READ", "operand": 468},
        {"mnemonic": "WRITE"},
        {"mnemonic": "ROR"}
    ]

    with open("test_program.json", "w", encoding="utf-8") as f:
        json.dump(test_program, f, indent=2, ensure_ascii=False)

    print("Создан тестовый JSON файл: test_program.json")

    # Также покажем содержимое файла
    print("\nСодержимое test_program.json:")
    print(json.dumps(test_program, indent=2, ensure_ascii=False))

    return test_program


def main():
    parser = argparse.ArgumentParser(description='Ассемблер УВМ v15 (JSON формат)')
    parser.add_argument('input', help='Файл .json с программой')
    parser.add_argument('output', help='Файл .bin для результата')
    parser.add_argument('--test', action='store_true', help='Режим тестирования')
    parser.add_argument('--create-test', action='store_true',
                        help='Создать тестовый JSON файл с примерами команд')

    args = parser.parse_args()

    if args.create_test:
        create_test_json_file()
        return

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Ошибка: файл '{input_path}' не найден")
        sys.exit(1)

    if input_path.suffix.lower() != '.json':
        print(f"Ошибка: входной файл должен быть в формате JSON (.json)")
        print(f"Используйте --create-test для создания примера JSON файла")
        sys.exit(1)

    print("\n[ЭТАП 1] Перевод программы в промежуточное представление")
    print(f"Чтение JSON файла: {input_path}")

    intermediate = parse_json_file(input_path)
    print(f"Прочитано команд из файла: {len(intermediate)}")

    if args.test:
        print("\nПромежуточное представление:")
        for i, instr in enumerate(intermediate):
            name = COMMAND_FORMATS[instr['op']]
            if 'B' in instr:
                print(f"  Команда {i}: операция={name}, поле B={instr['B']}")
            else:
                print(f"  Команда {i}: операция={name}")

    print("\n[ЭТАП 2] Формирование машинного кода")

    if args.test:
        print("\nПроверка кодирования команд:")
        if run_tests():
            print("  Все тесты пройдены успешно!")

    binary = encode_program(intermediate)

    print(f"\n2. Размер двоичного файла: {len(binary)} байт")

    if args.test:
        print("\n3. Вывод результата ассемблирования на экран в байтовом формате:")
        hex_bytes = []
        for i, b in enumerate(binary):
            hex_bytes.append(f"{b:02X}")
        print("  " + " ".join(hex_bytes))

        # Ожидаемая последовательность для тестовой программы
        expected = bytes([0xCD, 0x3D, 0x00, 0x4E, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x87])

        if binary == expected:
            print("\n  Результат совпадает с ожидаемым из спецификации!")
        else:
            print("\n  Полученный результат:")
            print(f"  Hex: {binary.hex()}")
            print(f"  Bytes: {list(binary)}")

    with open(output_path, 'wb') as f:
        f.write(binary)

    print(f"\n4. Результат сохранен в файл: {output_path}")
    print("\nАссемблирование завершено успешно!")


if __name__ == '__main__':
    main()