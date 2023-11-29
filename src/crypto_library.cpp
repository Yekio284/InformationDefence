#include <iostream>
#include <random>
#include <cmath>
#include <vector>
#include <map>
#include <string>
#include <utility>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <numeric>
#include "crypto_library.hpp"
#include "../external/PicoSHA2/picosha2.h"
#include "../external/ap/ap.hpp"

inline std::ostream &operator<<(std::ostream &out, __int128_t val) { // https://stackoverflow.com/questions/66053030/overload-of-stdostream-for-int128-t-ambiguous-when-called-from-a-namespace
    //Obviously not the real implementation, just here as an example
    return out << static_cast<uint64_t>(val);
}

template <typename T> // T = стандартные типы - int, ll, char, std::string, float...
inline std::ostream& operator<<(std::ostream &out, const std::pair<T, T> &pairToCout) {
	out << pairToCout.first;
	out << ' ';
	out << pairToCout.second;

	return out;
}

ll myCrypto::lab_first::powMod(__int128_t a, __int128_t x, __int128_t p) {
    ll result = 1;

	while (x) {
		//std::cout << "a = " << a << "\tx = " << x << "\tp = " << p << std::endl;
		if (x & 1) {
			result = (result * a) % p;
			--x;
		}
		else {
			a = (a * a) % p;
			x = x >> 1;
		}
    }

	return result;
}

ll myCrypto::lab_first::binPow(ll a, ll x) {
    ll result = 1;

	while (x) {
		if (x & 1) {
			result = result * a;
			--x;
		}
		else {
			a = a * a;
			x = x >> 1;
		}
    }

	return result;
}

std::vector<ll> myCrypto::lab_first::extendedGCD(ll a, ll b) {
	std::vector<ll> u_vec(3); // Возвращаемый вектор
	u_vec[0] = a;
	u_vec[1] = 1;
	u_vec[2] = 0;

	std::vector<ll> v_vec(3);
	v_vec[0] = b;
	v_vec[1] = 0;
	v_vec[2] = 1;

	while (v_vec[0] != 0) {
		ll q = u_vec[0] / v_vec[0];
		std::vector<ll> tmp_vec(3);
		
		tmp_vec[0] = u_vec[0] % v_vec[0];
		tmp_vec[1] = u_vec[1] - q * v_vec[1];
		tmp_vec[2] = u_vec[2] - q * v_vec[2];

		//std::cout << "t[0] = " << tmp_vec[0] << "\t\tt[1] = " << tmp_vec[1] << "\t\tt[2] = " << tmp_vec[2] << std::endl;

		u_vec = v_vec;
		v_vec = tmp_vec;
	}

	return u_vec; // (gcd, x, y)
}

bool myCrypto::lab_first::isPrime(ll n) {
	if (n < 2)
		return false;

	for (ll divider = 2; divider * divider <= n; divider++) {
		if (n % divider == 0)
			return false;
	}

	return true;
}

ll myCrypto::lab_first::random(ll a, ll b) {
	static std::random_device rand_device;
	static std::mt19937_64 engine(rand_device());
	std::uniform_int_distribution<ll> distribution(a, b);

	return distribution(engine);
}

ll myCrypto::lab_first::generatePrime() {
	ll n = 1;
	while (!myCrypto::lab_first::isPrime(n))
		n = myCrypto::lab_first::random(1e7, 1e9);
	
	return n;
}

ll myCrypto::lab_first::generateCommonKey() {
	namespace lw1 = myCrypto::lab_first;
	
	ll q = lw1::generatePrime(); // q - число Софи Жермен, 
	ll p = 2 * q + 1; 		     // p - безопасное простое число

	while (!isPrime(p)) {
		q = lw1::generatePrime();
		p = 2 * q + 1;
	}

	// std::cout << "q = " << q << "\tp = " << p << std::endl;

	ll g = 2; // первообразный корень по модулю p;
	for (g; g < p - 1 && lw1::powMod(g, q, p) == 1; g++);

	// std::cout << "g = " << g << std::endl;

	ll alice_private_key = lw1::random(lw1::binPow(10, 7), lw1::binPow(10, 9));
	ll bob_private_key = lw1::random(lw1::binPow(10, 7), lw1::binPow(10, 9));
	ll alice_public_key = lw1::powMod(g, alice_private_key, p);
	ll bob_public_key = lw1::powMod(g, bob_private_key, p);

	// std::cout << "alice_private_key = " << alice_private_key << "\tbob_private_key = " << bob_private_key <<
	//			 "\talice_pubilc_key = " << alice_public_key << "\tbob_public_key = " << bob_public_key << 
	//			 "\tp = " << p << std::endl;

	ll common_key = lw1::powMod(bob_public_key, alice_private_key, p);

	return common_key == lw1::powMod(alice_public_key, bob_private_key, p) ? common_key : -1;
}

ll myCrypto::lab_first::discreteLogarithm(ll a, ll p, ll y) {
	namespace lw1 = myCrypto::lab_first;

	ll m = std::ceil(std::sqrt(p));
	ll k = m;

	std::vector<ll> a_row(m);
	std::vector<ll> b_row(k);

	for (ll i = 0, j = 0; i < m && j < k; i++, j++) {
		a_row[i] = lw1::powMod(a, i, p) * y % p;
		b_row[j] = lw1::powMod(a, (j + 1) * m, p);
	}

	std::map<ll, ll> dict;
	ll index_i = 0, index_j = 0;

	//std::cout << "m = " << m << std::endl;

	for (ll i = 0; i < m; i++)
		dict[a_row[i]] = i;
	for (ll i = 0; i < k; i++) {
		if (dict.count(b_row[i])) {
			index_i = i + 1;
			index_j = dict[b_row[i]];
			//std::cout << index_i << ' ' << index_j << std::endl;
			break;
		}
	}

	return index_i * m - index_j;
}

ll myCrypto::lab_second::gcd(ll a, ll b) {
	return b ? gcd(b, a % b) : a;
}

std::vector<ll> myCrypto::lab_second::generateShamirParameters() {
	namespace lw1 = myCrypto::lab_first;
	namespace lw2 = myCrypto::lab_second;

	ll p = lw1::generatePrime();
    
	// Alice params
	ll cA = lw1::random(1e7, 1e9);
	while (lw2::gcd(cA, p - 1) != 1)
        cA = lw1::random(1e7, 1e9);
	ll buf_num = lw1::extendedGCD(cA, p - 1)[1];
	ll dA = buf_num < 0 ? buf_num + p - 1 : buf_num;
	
	// Bob params
	ll cB = lw1::random(1e7, 1e9);
	while (lw2::gcd(cB, p - 1) != 1)
        cB = lw1::random(1e7, 1e9);
	buf_num = lw1::extendedGCD(cB, p - 1)[1];
	ll dB = buf_num < 0 ? buf_num + p - 1 : buf_num;

	std::vector<ll> params(5);
	params[0] = cA;
	params[1] = dA;
	params[2] = cB;
	params[3] = dB;
	params[4] = p;

	return params; // cA, dA, cB, dB, p
}

void myCrypto::lab_second::encodeShamir(const std::string &inputFileName, const std::vector<ll> &params) {
    namespace lw1 = myCrypto::lab_first;

    std::ifstream input(inputFileName, std::ios::binary); // Открываем файл на чтение в бинарном формате
    std::ofstream encoded("encoded_" + inputFileName, std::ios::binary); // Открываем файл на запись в бинарном формате
	
	for (char element; input.read(&element, sizeof(element));) {
        ll x1 = lw1::powMod(static_cast<ll>(element), params[0], params[4]);
        ll x2 = lw1::powMod(x1, params[2], params[4]);
        ll x3 = lw1::powMod(x2, params[1], params[4]);
        encoded.write(reinterpret_cast<const char*>(&x3), sizeof(x3));
    }

    input.close();
    encoded.close();
}

void myCrypto::lab_second::decodeShamir(const std::string &encodedFileName, const std::vector<ll> &params) {
    namespace lw1 = myCrypto::lab_first;

    std::ifstream input(encodedFileName, std::ios::binary); // Открываем encoded файл на чтение в бинарном формате
    std::ofstream decoded("decoded_" + std::string(
        std::find(encodedFileName.begin(), encodedFileName.end(), '_') + 1, encodedFileName.end()), std::ios::binary); // Открываем файл на запись в бинарном формате

    for (ll x3; input.read(reinterpret_cast<char*>(&x3), sizeof(x3));) {
        ll x4 = lw1::powMod(x3, params[3], params[4]);
        char element = static_cast<char>(x4);
        decoded.write(&element, sizeof(element));
    }

    input.close();
    decoded.close();
}

std::vector<ll> myCrypto::lab_second::generateElgamalParameters(){ // функция генерации cA, dA, cB, dB, p, g
	namespace lw1 = myCrypto::lab_first;
	
	ll q = lw1::generatePrime(); // q - число Софи Жермен, 
	ll p = 2 * q + 1; 		     // p - безопасное простое число

	while (!lw1::isPrime(p)) {
		q = lw1::generatePrime();
		p = 2 * q + 1;
	}

	ll g = 2; // первообразный корень по модулю p;
	for (g; g < p - 1 && lw1::powMod(g, q, p) == 1; g++);

	ll cA = lw1::random(1, p - 1);
	ll dA = lw1::powMod(g, cA, p);
	
	ll cB = lw1::random(1, p - 1);
	ll dB = lw1::powMod(g, cB, p);

	std::vector<ll>	params(6);
	params[0] = cA;
	params[1] = dA;
	params[2] = cB;
	params[3] = dB;
	params[4] = p;
	params[5] = g;

	return params; // cA, dA, cB, dB, p, g
} 

std::vector<ll> myCrypto::lab_second::encodeElgamal(const std::string &inputFileName, const std::vector<ll> &params) {
	namespace lw1 = myCrypto::lab_first;

    std::ifstream input(inputFileName, std::ios::binary); // Открываем файл на чтение в бинарном формате
    std::ofstream encoded("encoded_" + inputFileName, std::ios::binary); // Открываем файл на запись в бинарном формате

	std::vector<ll> R_keys; // r
	for (char element; input.read(&element, sizeof(element));) {
        ll k = lw1::random(0, params[4] - 1);
		ll r = lw1::powMod(params[5], k, params[4]);
		ll e = lw1::powMod(params[3], k, params[4]) * static_cast<ll>(element) % params[4];
        encoded.write(reinterpret_cast<const char*>(&e), sizeof(e));
		
		R_keys.push_back(r);
    }

	input.close();
	encoded.close();

	R_keys.shrink_to_fit();

	return R_keys;
}

void myCrypto::lab_second::decodeElgamal(const std::string &encodedFileName, const std::vector<ll> &params, const std::vector<ll> &R_keys) {
	namespace lw1 = myCrypto::lab_first;

    std::ifstream input(encodedFileName, std::ios::binary); // Открываем encoded файл на чтение в бинарном формате
    std::ofstream decoded("decoded_" + std::string(
        std::find(encodedFileName.begin(), encodedFileName.end(), '_') + 1, encodedFileName.end()), std::ios::binary); // Открываем файл на запись в бинарном формате
	
	int i = 0;
	for (ll e; input.read(reinterpret_cast<char*>(&e), sizeof(e)); i++) {
        ll m = lw1::powMod(R_keys[i], params[4] - 1 - params[2], params[4]) * e % params[4];
        char element = static_cast<char>(m);
        decoded.write(&element, sizeof(element));
    }

    input.close();
    decoded.close();
}

std::vector<ll> myCrypto::lab_second::generateRSAParameters() { // cB, dB, nB
	namespace lw1 = myCrypto::lab_first;
	namespace lw2 = myCrypto::lab_second;

	ll pB = lw1::generatePrime();
	ll qB = lw1::generatePrime();
	ll nB = pB * qB;
	ll phi = (pB - 1) * (qB - 1);
	ll dB = lw1::random(1e7, phi);
	while (lw2::gcd(dB, phi) != 1)
		dB = lw1::random(1e7, phi);
	ll buf_num = lw1::extendedGCD(dB, phi)[1];
	ll cB = buf_num < 0 ? buf_num + phi : buf_num;
	
	// std::cout << "phi = " << phi << "\tp = " << pB << "\tq = " << qB << std::endl;
	
	return std::vector<ll>({cB, dB, nB}); // cB, dB, nB
}

void myCrypto::lab_second::encodeRSA(const std::string &inputFileName, const std::vector<ll> &params) {
	namespace lw1 = myCrypto::lab_first;

    std::ifstream input(inputFileName, std::ios::binary); // Открываем файл на чтение в бинарном формате
    std::ofstream encoded("encoded_" + inputFileName, std::ios::binary); // Открываем файл на запись в бинарном формате

	for (char element; input.read(&element, sizeof(element));) {
		ll e = lw1::powMod(static_cast<ll>(element), params[1], params[2]);
        encoded.write(reinterpret_cast<const char*>(&e), sizeof(e));
    }

	input.close();
	encoded.close();
}

void myCrypto::lab_second::decodeRSA(const std::string &encodedFileName, const std::vector<ll> &params) {
	namespace lw1 = myCrypto::lab_first;

    std::ifstream input(encodedFileName, std::ios::binary); // Открываем encoded файл на чтение в бинарном формате
    std::ofstream decoded("decoded_" + std::string(
        std::find(encodedFileName.begin(), encodedFileName.end(), '_') + 1, encodedFileName.end()), std::ios::binary); // Открываем файл на запись в бинарном формате
	
	for (ll e; input.read(reinterpret_cast<char*>(&e), sizeof(e));) {
        ll m = lw1::powMod(e, params[0], params[2]);
        char element = static_cast<char>(m);
        decoded.write(&element, sizeof(element));
    }

    input.close();
    decoded.close();
}

std::string myCrypto::lab_second::encodeVernam(const std::string &inputFileName) {
	namespace lw1 = myCrypto::lab_first;

    std::ifstream input(inputFileName, std::ios::binary); // Открываем файл на чтение в бинарном формате
    std::ofstream encoded("encoded_" + inputFileName, std::ios::binary); // Открываем файл на запись в бинарном формате

	std::string key;
	for (char element; input.read(&element, sizeof(element));) {
		std::random_device rd;
		std::mt19937 engine(rd());
		std::uniform_int_distribution<> distribution(0, 255);
		key.push_back(distribution(engine));
		
		char encodedChar = element ^ key.back();

		encoded.write(&encodedChar, sizeof(encodedChar));
	}

	return key;
}

void myCrypto::lab_second::decodeVernam(const std::string &encodedFileName, const std::string &key) {
	std::ifstream input(encodedFileName, std::ios::binary); // Открываем encoded файл на чтение в бинарном формате
    std::ofstream decoded("decoded_" + std::string(
        std::find(encodedFileName.begin(), encodedFileName.end(), '_') + 1, encodedFileName.end()), std::ios::binary); // Открываем файл на запись в бинарном формате
	
	ll i = 0;
	for (char element; input.read(&element, sizeof(element)); i++) {
		char decodedChar = element ^ key[i];
		decoded.write(&decodedChar, sizeof(decodedChar));
	}
}

std::string myCrypto::lab_third::computeHashFromFile(std::ifstream &file) {
	std::vector<unsigned char> bytes_hash_vec(picosha2::k_digest_size);
	picosha2::hash256(file, bytes_hash_vec.begin(), bytes_hash_vec.end());

	return picosha2::bytes_to_hex_string(bytes_hash_vec).substr(0, 7);
}

ll myCrypto::lab_third::hexToDecimal(const std::string &hex_str) {
	std::stringstream ss;
	ss << std::hex << hex_str;
	
	ll decimal_result;
	ss >> decimal_result;

	return decimal_result;
}

ll myCrypto::lab_third::generateBigPrime() {
	ll n = 1;
	while (!myCrypto::lab_first::isPrime(n))
		n = myCrypto::lab_first::random(3e8, 1e9);
	
	return n;
}

void myCrypto::lab_third::signRSA(const std::string &inputFileName, const std::vector<ll> &params) {
	namespace lw1 = myCrypto::lab_first;
	namespace lw3 = myCrypto::lab_third;

	std::ifstream input(inputFileName, std::ios::binary); // открываем файл на чтение в бинарном формате
	
	std::string hash_str = lw3::computeHashFromFile(input); // Вычисляем hash файла и записываем его в строку в виде 16-ричного числа. (алгоритм PicoSHA2)
	ll hash_ll = lw3::hexToDecimal(hash_str); // Переводим hex в decimal
	
	//std::cout << "hash_str = " << hash_str << std::endl;
	//std::cout << "hash_ll = " << hash_ll << std::endl;

	input.seekg(0); // Переместим "каретку" на начало файла в виду того, что она сдвинулась в конец при работе с PicoSHA2
	
	std::ofstream signedFile("signed_" + inputFileName, std::ios::binary); // открываем файл на запись в бинарном формате
	signedFile << input.rdbuf(); // Делаем копию файла
	signedFile.seekp(signedFile.tellp()); // Смещаем позицию записи в конец
	input.close(); // Закрываем input
	
	ll s = lw1::powMod(hash_ll, params[0], params[2]); // s = y^(c)mod(N)
	
	//std::cout << "\tcB = " << params[0] << "\tnB = " << params[2] << "\ts = " << s << std::endl;

	signedFile.write(reinterpret_cast<const char*>(&s), sizeof(s)); // Подписываем документ
}

bool myCrypto::lab_third::checkSignRSA(const std::string &fileNameToCheck, const std::vector<ll> &params) {
	namespace lw1 = myCrypto::lab_first;
	namespace lw3 = myCrypto::lab_third;
	namespace fs = std::filesystem;
	
	std::ifstream file(fileNameToCheck, std::ios::binary);
	const std::string copy_name = "copy_" + fileNameToCheck;
	std::ofstream copyFile(copy_name, std::ios::binary);

	copyFile << file.rdbuf(); // Делаем копию файла "signed_<...>" или любого другого заданного в fileNameToCheck
	copyFile.close();

	file.seekg(fs::file_size(fileNameToCheck) - sizeof(ll));
	ll s;
	file.read(reinterpret_cast<char*>(&s), sizeof(ll));
	file.close();
	if (s < 0) {
		std::remove(copy_name.c_str());
		return false;
	}

	const auto path_to_file = fs::path(copy_name);
	fs::resize_file(path_to_file, fs::file_size(path_to_file) - sizeof(ll)); // Переопредялем размер файла "copy_<..>", т.е., 
																			 //	грубо говоря, убираем предполагаемую цифровую подпись

	file.open(copy_name, std::ios::binary); // Открываем файл "copy_<...>"
	std::string hash_str = lw3::computeHashFromFile(file);
	ll hash_ll = lw3::hexToDecimal(hash_str);
	
	file.close(); // Закрываем файл "copy_<...>"
	std::remove(copy_name.c_str()); // Удаляем файл "copy_<...>"
	
	ll w = lw1::powMod(s, params[1], params[2]); // Вычисляем w
	
	//std::cout << "HashCheck_str = " << hash_str << "\nHashCheck_ll = " << hash_ll << std::endl;
	//std::cout << "w = " << w << "\th(m) = " << hash_ll << std::endl;

	return w == hash_ll;
}

std::vector<ll> myCrypto::lab_third::generateSignElgamalParameters() {
	namespace lw1 = myCrypto::lab_first;
	namespace lw3 = myCrypto::lab_third;
	
	ll q = lw3::generateBigPrime(); // q - число Софи Жермен, 
	ll p = 2 * q + 1; 		     	// p - безопасное простое число

	while (!lw1::isPrime(p)) {
		q = lw3::generateBigPrime();
		p = 2 * q + 1;
	}

	ll g = 2; // первообразный корень по модулю p;
	for (g; g < p - 1 && lw1::powMod(g, q, p) == 1; g++);

	ll x = lw1::random(2, p - 2);
	ll y = lw1::powMod(g, x, p);

	return std::vector<ll>({g, p, x, y});
}

void myCrypto::lab_third::signElgamal(const std::string &inputFileName, const std::vector<ll> &params) {
	namespace lw1 = myCrypto::lab_first;
	namespace lw2 = myCrypto::lab_second;
	namespace lw3 = myCrypto::lab_third;
	
	std::ifstream input(inputFileName, std::ios::binary); // открываем файл на чтение в бинарном формате
	
	std::string hash_str = lw3::computeHashFromFile(input); // Вычисляем hash файла и записываем его в строку в виде 16-ричного числа. (алгоритм PicoSHA2)
	ll hash_ll = lw3::hexToDecimal(hash_str); // Переводим hex в decimal

	//std::cout << "hash_str = " << hash_str << std::endl;
	//std::cout << "hash_ll = " << hash_ll << std::endl;

	// Нет проверки на 1 < h < p т.к. максимальное значение h = 268'435'455. Диапазон генерации p начинается с 3e8
	
	input.seekg(0); // Переместим "каретку" на начало файла в виду того, что она сдвинулась в конец при работе с PicoSHA2
	
	std::ofstream signedFile("signed_" + inputFileName, std::ios::binary); // открываем файл на запись в бинарном формате
	signedFile << input.rdbuf(); // Делаем копию файла
	signedFile.seekp(signedFile.tellp()); // Смещаем позицию записи в конец
	input.close(); // Закрываем input

	ll k = lw1::random(2, params[1] - 2);
	while (lw2::gcd(k, params[1] - 1) != 1)
		k = lw1::random(2, params[1] - 2);

	ll r = lw1::powMod(params[0], k, params[1]);

	//std::cout << "k = " << k << std::endl;
	//std::cout << "r = " << r << std::endl;
	
	ll buf1 = hash_ll - params[2] * r;
	ll buf2 = params[1] - 1;
	ll u = (buf1 % buf2 + buf2) % buf2;
	ll k_inversed = lw1::extendedGCD(k, params[1] - 1)[1];
	if (k_inversed < 0)
		k_inversed = k_inversed + params[1] - 1;
	
	buf1 = k_inversed * u;
	buf2 = params[1] - 1;
	ll s = buf1 % buf2;
	
	//std::cout << "u = " << u << std::endl;
	//std::cout << "k_inversed = " << k_inversed << std::endl;
	//std::cout << "s = " << s << std::endl;

	// Подписываем документ
	signedFile.write(reinterpret_cast<const char*>(&r), sizeof(r));
	signedFile.write(reinterpret_cast<const char*>(&s), sizeof(s)); 
}

bool myCrypto::lab_third::checkSignElgamal(const std::string &fileNameToCheck, const std::vector<ll> &params) {
	namespace lw1 = myCrypto::lab_first;
	namespace lw3 = myCrypto::lab_third;
	namespace fs = std::filesystem;
	
	std::ifstream file(fileNameToCheck, std::ios::binary);
	const std::string copy_name = "copy_" + fileNameToCheck;
	std::ofstream copyFile(copy_name, std::ios::binary);

	copyFile << file.rdbuf(); // Делаем копию файла "signed_<...>" или любого другого заданного в fileNameToCheck
	copyFile.close();

	file.seekg(fs::file_size(fileNameToCheck) - 2 * sizeof(ll));
	ll r, s;
	file.read(reinterpret_cast<char*>(&r), sizeof(ll));
	file.read(reinterpret_cast<char*>(&s), sizeof(ll));
	file.close();
	if (r < 0 || s < 0) {
		std::remove(copy_name.c_str());
		return false;
	}

	const auto path_to_file = fs::path(copy_name);
	fs::resize_file(path_to_file, fs::file_size(path_to_file) - 2 * sizeof(ll)); // Переопредялем размер файла "copy_<..>", т.е., 
																			 //	грубо говоря, убираем предполагаемую цифровую подпись

	file.open(copy_name, std::ios::binary); // Открываем файл "copy_<...>"
	std::string hash_str = lw3::computeHashFromFile(file);
	ll hash_ll = lw3::hexToDecimal(hash_str);
	
	//std::cout << "Check_hash_str = " << hash_str << std::endl;
	//std::cout << "Check_hash_ll = " << hash_ll << std::endl;
	
	file.close(); // Закрываем файл "copy_<...>"
	std::remove(copy_name.c_str()); // Удаляем файл "copy_<...>"
	ll buf1 = (lw1::powMod(params[3], r, params[1]) * lw1::powMod(r, s, params[1])) % params[1];
	ll buf2 = lw1::powMod(params[0], hash_ll, params[1]);

	//std::cout << "buf1 = " << buf1 << "\tbuf2 = " << buf2 << std::endl;

	return buf1 == buf2;
}

std::vector<ll> myCrypto::lab_third::generateSignGOSTParameters() {
	namespace lw1 = myCrypto::lab_first;
	namespace lw3 = myCrypto::lab_third;

	ll b, q, p;
	do {
		b = lw1::random(2, 1e7);
		q = lw3::generateBigPrime();
		p = b * q + 1;
	} while (!lw1::isPrime(p));

	ll a;
	do {
		ll g = lw1::random(2, 1e8);
		a = lw1::powMod(g, (p - 1) / q, p);
	} while (lw1::powMod(a, q, p) != 1);

	ll x = lw1::random(1, q - 1);
	ll y = lw1::powMod(a, x, p);
	
	//std::cout << "b = " << b << "\tq = " << q << "\tp = " << p << "\ta = " << a << "\tx = " << x << "\ty = " << y << std::endl;

	return std::vector<ll>({p, q, a, x, y});
}

void myCrypto::lab_third::signGOST(const std::string &inputFileName, const std::vector<ll> &params) {
	namespace lw1 = myCrypto::lab_first;
	namespace lw3 = myCrypto::lab_third;
	
	std::ifstream input(inputFileName, std::ios::binary);

	std::string hash_str = lw3::computeHashFromFile(input);
	ll hash_ll = lw3::hexToDecimal(hash_str);

	input.seekg(0); // Переместим "каретку" на начало файла в виду того, что она сдвинулась в конец при работе с PicoSHA2
	
	std::ofstream signedFile("signed_" + inputFileName, std::ios::binary); // открываем файл на запись в бинарном формате
	signedFile << input.rdbuf(); // Делаем копию файла
	signedFile.seekp(signedFile.tellp()); // Смещаем позицию записи в конец
	input.close(); // Закрываем input

	//std::cout << "hash_str = " << hash_str << std::endl;
	//std::cout << "hash_ll = " << hash_ll << std::endl;

	ll k, r, s;
	do {
		k = lw1::random(1, params[1]);
		r = (lw1::powMod(params[2], k, params[0])) % params[1];
		s = (k * hash_ll + params[3] * r) % params[1];
	} while (r == 0 || s == 0);

	//std::cout << "k = " << k << "\tr = " << r << "\ts = " << s << std::endl;

	signedFile.write(reinterpret_cast<const char*>(&r), sizeof(r));
	signedFile.write(reinterpret_cast<const char*>(&s), sizeof(s));
}

bool myCrypto::lab_third::checkSignGOST(const std::string &fileNameToCheck, const std::vector<ll> &params) {
	namespace lw1 = myCrypto::lab_first;
	namespace lw3 = myCrypto::lab_third;
	namespace fs = std::filesystem;
	
	std::ifstream file(fileNameToCheck, std::ios::binary);
	const std::string copy_name = "copy_" + fileNameToCheck;
	std::ofstream copyFile(copy_name, std::ios::binary);

	copyFile << file.rdbuf(); // Делаем копию файла "signed_<...>" или любого другого заданного в fileNameToCheck
	//file.close();
	copyFile.close();

	file.seekg(fs::file_size(fileNameToCheck) - 2 * sizeof(ll));
	ll r, s;
	file.read(reinterpret_cast<char*>(&r), sizeof(ll));
	file.read(reinterpret_cast<char*>(&s), sizeof(ll));
	file.close();

	const auto path_to_file = fs::path(copy_name);
	fs::resize_file(path_to_file, fs::file_size(path_to_file) - 2 * sizeof(ll)); // Переопредялем размер файла "copy_<..>", т.е., 
																			     //	грубо говоря, убираем предполагаемую цифровую подпись

	file.open(copy_name, std::ios::binary); // Открываем файл "copy_<...>"
	std::string hash_str = lw3::computeHashFromFile(file);
	ll hash_ll = lw3::hexToDecimal(hash_str);
	
	file.close(); // Закрываем файл "copy_<...>"
	std::remove(copy_name.c_str()); // Удаляем файл "copy_<...>"

	if (r >= params[1] || s >= params[1] || r <= 0 || s <= 0)
		return false;
	
	ll h_inverted = lw1::extendedGCD(hash_ll, params[1])[1];
	if (h_inverted < 0)
		h_inverted = h_inverted + params[1];
	
	ll u1 = (s * h_inverted) % params[1];
	ll u2 = ((r * -1) * h_inverted) % params[1];
	u2 = u2 < 0 ? u2 + params[1] : u2;
	
	ll v = (static_cast<__int128_t>(lw1::powMod(params[2], u1, params[0])) * 
		static_cast<__int128_t>(lw1::powMod(params[4], u2, params[0])) % params[0]) % params[1];

	//std::cout << "Check_hash_str = " << hash_str << "\tCheck_hash_ll = " << hash_ll << "\th_inv = " << 
	//	h_inverted << "\nu1 = " << u1 << "\tu2 = " << u2 << std::endl;
	//std::cout << "v = " << v << std::endl;
	
	return v == r;
}

myCrypto::lab_fourth::Game::Game() : fullCardNames(52), p(0) { // Конструктор класса Game. При создании объекта
	namespace lw1 = myCrypto::lab_first;                       // класса Game вместе с ним сгенерируется число "p"
	
	char i = 0;
	for (const std::string &name : cardName) {
        for (const std::string &suit : suits) {
            fullCardNames[i] = name + suit;
            i++;
        }
    }

	ll q; // q - число Софи Жермен, 
	do {
		q = lw1::generatePrime();
		p = 2 * q + 1;
	} while (!lw1::isPrime(p));

	// std::cout << "p = " << p << "\tq = " << q << std::endl;
}

ll myCrypto::lab_fourth::Game::getP() const {
	return p;
}

std::map<ll, std::string> myCrypto::lab_fourth::Game::generateDeck() const {
	namespace lw1 = myCrypto::lab_first;
	
	std::map<ll, std::string> resMap;
	ll keyNum;
	
	std::for_each(fullCardNames.begin(), fullCardNames.end(), [this, &resMap, &keyNum](std::string name){
		do {
			keyNum = lw1::random(2, p - 1);
		} while (resMap.contains(keyNum));
		
		resMap[keyNum] = name;
	});

	return resMap;
}

void myCrypto::lab_fourth::Game::giveEncryptedCardsToPlayers(const std::vector<ll> &cards, std::vector<myCrypto::lab_fourth::Player> &players) const {
	for (short j = 0, k = 0; k < players.size(); j = j + 2, k++) {
		players[k].setEncryptedCards(std::make_pair(cards[j], cards[j + 1])); 
	}
}

myCrypto::lab_fourth::Game::~Game() {
	std::cout << "Thanks for playing!" << std::endl;
}

myCrypto::lab_fourth::Player::Player() {}

myCrypto::lab_fourth::Player::Player(const ll &p) : c(0), d(0) {
	namespace lw1 = myCrypto::lab_first;
	namespace lw2 = myCrypto::lab_second;

	do {
		c = lw1::random(1e7, 1e9);
	} while (lw2::gcd(c, p - 1) != 1);

	d = lw1::extendedGCD(c, p - 1)[1];
	if (d < 0)
		d = d + p - 1;
	
	// std::cout << "\tc = " << c << "\td = " << d << std::endl;
	// std::cout << std::boolalpha << ((c * d) % (p - 1) == 1) << std::endl;
}

void myCrypto::lab_fourth::Player::encryptAndShuffleDeck(const ll &p, std::vector<ll> &nums) const {
	namespace lw1 = myCrypto::lab_first;

	for (auto &element : nums)
		element = lw1::powMod(element, c, p);
	
	static std::random_device rand_device;
	static std::mt19937 engine(rand_device());
	std::shuffle(nums.begin(), nums.end(), engine);
}

void myCrypto::lab_fourth::Player::setEncryptedCards(const std::pair<ll, ll> encryptedCards) {
	this->encryptedCards = encryptedCards;
}

ll myCrypto::lab_fourth::Player::getLeftEncryptedCard() const {
	return encryptedCards.first;
}

ll myCrypto::lab_fourth::Player::getRightEncryptedCard() const {
	return encryptedCards.second;
}

ll myCrypto::lab_fourth::Player::getC() const {
	return c;
}

ll myCrypto::lab_fourth::Player::getD() const {
	return d;
}

void myCrypto::lab_fourth::Player::decryptAndSetCards(const std::vector<myCrypto::lab_fourth::Player> &players, std::map<ll, std::string> &deck, 
													  const ll &p, const short i) {
	namespace lw1 = myCrypto::lab_first;
	
	ll leftCard = getLeftEncryptedCard(), rightCard = getRightEncryptedCard();
	
	for (short j = 0; j < players.size(); j++) {
		if (j != i) {
			leftCard = lw1::powMod(leftCard, players[j].getD(), p);
			rightCard = lw1::powMod(rightCard, players[j].getD(), p);
		}
	}

	leftCard = lw1::powMod(leftCard, d, p);
	rightCard = lw1::powMod(rightCard, d, p);

	// std::cout << leftCard << ' ' << rightCard << std::endl;

	decryptedCards = std::make_pair(deck[leftCard], deck[rightCard]);
}

void myCrypto::lab_fourth::Player::showCards() const {
	std::cout << decryptedCards << std::endl;
}

myCrypto::lab_fourth::Player::~Player() {}

myCrypto::lab_fifth::Server::Server() : c(0), d(0), n(0), address(0), voters(0) {
	namespace lw1 = myCrypto::lab_first;
	namespace lw2 = myCrypto::lab_second;

	std::vector<ll> RSA_Parameters = lw2::generateRSAParameters();

	c = RSA_Parameters[0];
	d = RSA_Parameters[1];
	n = RSA_Parameters[2];

	address = lw1::random(1e5, 1e7);

	std::ofstream database("database.csv", std::ios::app);
	database << "id;n;s\n";
	database.close();

	// std::cout << "c = " << c << "\td = " << d << "\tn = " << n << std::endl;
	// std::cout << "address = " << address << std::endl;
}

ll myCrypto::lab_fifth::Server::addVoterAndComputeS1(const ll &id, const ll &h1) {
	namespace lw1 = myCrypto::lab_first;
	
	if (std::find(voters.begin(), voters.end(), id) != voters.end()) // если нашли id в voters
		return -1;
	
	voters.push_back(id);

	return lw1::powMod(h1, c, n);
}

bool myCrypto::lab_fifth::Server::recieveBulletinAndAddToDB(const ll &n, const ll &s, const ll &id) const {
	namespace lw1 = myCrypto::lab_first;

	std::string nStr = std::to_string(n);

	std::vector<unsigned char> bytes_hash_vec(picosha2::k_digest_size);
	picosha2::hash256(nStr.begin(), nStr.end(), bytes_hash_vec.begin(), bytes_hash_vec.end());

	ap_uint<256> hash = 0;
	for (const auto &item : bytes_hash_vec) {
		hash = (hash << 8) | item;
	}	

	hash = hash % this->n;
	
	// std::cout << hash << std::endl;
	// std::cout << lw1::powMod(s, d, this->n) << std::endl;

	std::ofstream database("database.csv", std::ios::app);
	if (hash == lw1::powMod(s, d, this->n)) {
		database << id << ';' << n << ';' << s << '\n';
		database.close();
		
		return true;
	}
	database.close();

	return false;
}

ll myCrypto::lab_fifth::Server::getC() const {
	return c;
}

ll myCrypto::lab_fifth::Server::getD() const {
	return d;
}

ll myCrypto::lab_fifth::Server::getN() const {
	return n;
}

ll myCrypto::lab_fifth::Server::getAddress() const {
	return address;
}

myCrypto::lab_fifth::Server::~Server() {}

myCrypto::lab_fifth::Client::Client() : rnd(myCrypto::lab_first::random(1e7, 1e9)), n(0), r(0), 
	id(++count), h(0), h1(0), s1(0), s(0) {}

void myCrypto::lab_fifth::Client::setVote(const char vote) {
	this->vote = vote;
}

void myCrypto::lab_fifth::Client::setS1(const ll &s1) {
	this->s1 = s1;
}

void myCrypto::lab_fifth::Client::generate_n(const ll &address) {
	namespace lw1 = myCrypto::lab_first;
	
	ll rnd_copy = rnd;
	rnd_copy = rnd_copy * 10 + vote;
	
	n = rnd_copy * lw1::binPow(10, (ll)std::log10(address) + 1) + address;

	// std::cout << "rnd = " << rnd << "\taddress = " << address << "\tvote = " << (short)vote << std::endl;
	// std::cout << "n = " << n << std::endl;
}

void myCrypto::lab_fifth::Client::generate_r(const ll &n) {
	namespace lw1 = myCrypto::lab_first;
	namespace lw2 = myCrypto::lab_second;

	do {
		r = lw1::random(1e7, 1e9);
	} while (lw2::gcd(r, n) != 1);

	// std::cout << "r = " << r << std::endl;
}

void myCrypto::lab_fifth::Client::generate_h(const ll &n) {
	std::string nStr = std::to_string(this->n);

	std::vector<unsigned char> bytes_hash_vec(picosha2::k_digest_size);
	picosha2::hash256(nStr.begin(), nStr.end(), bytes_hash_vec.begin(), bytes_hash_vec.end());

	// for (const auto &item : bytes_hash_vec) {
	// 	std::cout << "item: " << (int)item << std::endl;
	// }

	for (const auto &item : bytes_hash_vec) {
		h = (h << 8) | item;
	}	

	h = h % n;
	// std::cout << "h = " << h << std::endl;
 
    // nStr = picosha2::bytes_to_hex_string(bytes_hash_vec);
	// std::cout << "nStr = " << nStr << std::endl;
}

void myCrypto::lab_fifth::Client::compute_h1(const ll &d, const ll &n) {
	namespace lw1 = myCrypto::lab_first;
	
	h1 = static_cast<ll>(((h % n) * (lw1::powMod(r, d, n))) % n);

	// std::cout << static_cast<ll>(h % n) << std::endl;
	// std::cout << lw1::powMod(r, d, n) << std::endl;
	// std::cout << h1 << std::endl;
}

void myCrypto::lab_fifth::Client::compute_s(const ll &n) {
	namespace lw1 = myCrypto::lab_first;

	ll r_inversed = lw1::extendedGCD(r, n)[1];
	if (r_inversed < 0)
		r_inversed = r_inversed + n;
	
	s = (static_cast<__int128_t>(s1 % n) * static_cast<__int128_t>(r_inversed % n)) % n;

	// std::cout << "s = " << s << "\ts1 = " << s1 << "\tr_inv = " << r_inversed << "\tn = " << n << std::endl;
}

ll myCrypto::lab_fifth::Client::getN() const {	
	return n;
}

ll myCrypto::lab_fifth::Client::getR() const {
	return r;
}

ll myCrypto::lab_fifth::Client::getId() const {
	return id;
}

ll myCrypto::lab_fifth::Client::getH1() const {
	return h1;
}

ll myCrypto::lab_fifth::Client::getS() const {
	return s;
}

char myCrypto::lab_fifth::Client::getVote() const {
	return vote;
}

myCrypto::lab_fifth::Client::~Client() {}