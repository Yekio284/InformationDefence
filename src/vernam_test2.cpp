#include <algorithm>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <vector>

// Функция для шифрования/дешифровки содержимого файла с помощью Vernam-шифра
std::string vernamEncryptDecrypt(
    const std::string& text,
    const std::string& key) {
  std::string result;
  for (std::size_t i = 0; i < text.size(); ++i) {
    char encodedChar = text[i] ^ key[i % key.size()];
    result.push_back(encodedChar);
  }
  return result;
}

int main() {
  std::string inputFileName =
      "Ryan_Gosling.jpg";  // путь к файлу с исходным текстом
  std::string encryptedOutputFileName =
      "encrypted_output.txt";  // путь к файлу для записи зашифрованного текста
  std::string decryptedOutputFileName =
      "decrypted_output.jpg";  // путь к файлу для записи дешифрованного текста

  std::ifstream input(inputFileName, std::ios::binary);
  if (!input) {
    std::cerr << "Не удалось открыть файл для чтения: " << inputFileName
              << std::endl;
    return 1;
  }

  std::ofstream encryptedOutput(encryptedOutputFileName, std::ios::binary);
  if (!encryptedOutput) {
    std::cerr << "Не удалось открыть файл для записи: "
              << encryptedOutputFileName << std::endl;
    return 1;
  }

  std::ofstream decryptedOutput(decryptedOutputFileName, std::ios::binary);
  if (!decryptedOutput) {
    std::cerr << "Не удалось открыть файл для записи: "
              << decryptedOutputFileName << std::endl;
    return 1;
  }

  // Чтение содержимого файла
  std::string text(
      (std::istreambuf_iterator<char>(input)),
      std::istreambuf_iterator<char>());
  input.close();

  // Генерация случайного ключа такой же длины, как и исходный текст
  std::string key;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 255);
  std::generate_n(
      std::back_inserter(key), text.size(), [&]() { return dis(gen); });

  // Шифрование текста
  std::string encryptedText = vernamEncryptDecrypt(text, key);

  // Запись зашифрованного текста в файл
  encryptedOutput << encryptedText;
  encryptedOutput.close();

  std::cout << "Текст успешно зашифрован и записан в файл: "
            << encryptedOutputFileName << std::endl;

  // Дешифровка текста
  std::string decryptedText = vernamEncryptDecrypt(encryptedText, key);

  // Запись дешифрованного текста в файл
  decryptedOutput << decryptedText;
  decryptedOutput.close();

  std::cout << "Текст успешно дешифрован и записан в файл: "
            << decryptedOutputFileName << std::endl;

  return 0;
}
