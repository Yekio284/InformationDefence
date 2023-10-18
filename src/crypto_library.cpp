#include <iostream>
#include <random>
#include <cmath>
#include <vector>
#include <map>
#include <string>
#include <utility>
#include <algorithm>
#include "crypto_library.hpp"

ll myCrypto::lab_first::powMod(ll a, ll x, ll p) {
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
	while (!isPrime(n))
		n = myCrypto::lab_first::random(myCrypto::lab_first::binPow(10, 7), 
										myCrypto::lab_first::binPow(10, 9));
	
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