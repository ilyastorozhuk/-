import pefile
import os

def analyze_pe_file(file_path):
    try:
        if not os.path.exists(file_path):
            print("Файл не знайдено.")
            return

        # Завантаження PE-файлу
        pe = pefile.PE(file_path)

        print(f"Аналіз файлу: {file_path}\n")

        # Отримання імпортованих бібліотек і функцій
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("Імпортовані бібліотеки та функції:")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"Бібліотека: {entry.dll.decode('utf-8')}")
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8') if imp.name else 'N/A'
                    print(f"  Функція: {func_name}")
        else:
            print("Імпортовані бібліотеки відсутні або недоступні.")

        # Закриття PE-файлу
        pe.close()

    except pefile.PEFormatError as e:
        print(f"Помилка формату PE-файлу: {e}")
    except Exception as e:
        print(f"Помилка: {e}")

if __name__ == "__main__":
    file_path = input("Введіть шлях до PE-файлу: ").strip()
    analyze_pe_file(file_path)
