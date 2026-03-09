#pragma once
#include <string>
#include <string_view>
#include <random>
namespace {
static std::mt19937& rng() {
    static thread_local std::mt19937 gen(std::random_device{}());
    return gen;
}

static std::string generate_lib_name() {
    static constexpr std::string_view alphabet = "abcdefghijklmnopqrstuvwxyz";
    std::uniform_int_distribution<int> len_dist(3, 6);
    std::uniform_int_distribution<size_t> pick(0, alphabet.size() - 1);

    const int len = len_dist(rng());

    std::string name;
    name.reserve(3 + len + 3);
    name += "lib";
    for (int i = 0; i < len; ++i) {
        name.push_back(alphabet[pick(rng())]);
    }
    name += ".so";
    return name;
}

}
