#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace secure {

inline constexpr std::size_t kSharedSecretBytes = 32U;
inline constexpr std::size_t kSharedSecretTextLength = 43U;

enum class SharedSecretValidationError {
    None,
    WrongLength,
    InvalidCharacter,
    NonCanonicalEncoding,
    ObviousLowEntropyPattern,
};

namespace detail {

[[nodiscard]] constexpr std::uint8_t base64url_value(
    const std::uint8_t character) noexcept {
    if (character >= static_cast<std::uint8_t>('A') &&
        character <= static_cast<std::uint8_t>('Z')) {
        return static_cast<std::uint8_t>(character -
                                         static_cast<std::uint8_t>('A'));
    }
    if (character >= static_cast<std::uint8_t>('a') &&
        character <= static_cast<std::uint8_t>('z')) {
        return static_cast<std::uint8_t>(26U + character -
                                         static_cast<std::uint8_t>('a'));
    }
    if (character >= static_cast<std::uint8_t>('0') &&
        character <= static_cast<std::uint8_t>('9')) {
        return static_cast<std::uint8_t>(52U + character -
                                         static_cast<std::uint8_t>('0'));
    }
    if (character == static_cast<std::uint8_t>('-')) return 62U;
    if (character == static_cast<std::uint8_t>('_')) return 63U;
    return 0xFFU;
}

} // namespace detail

// TrueTunnel accepts generated keys, not human passwords. The exact length,
// alphabet, and final quantum enforce one canonical unpadded base64url encoding
// of 32 bytes. The additional checks reject conspicuous hand-authored/repeated
// values; they are a misuse guard, not an entropy estimator or a PAKE.
[[nodiscard]] inline SharedSecretValidationError validate_shared_secret(
    const std::span<const std::uint8_t> value) noexcept {
    if (value.size() != kSharedSecretTextLength) {
        return SharedSecretValidationError::WrongLength;
    }

    std::array<std::uint8_t, kSharedSecretTextLength> encoded_values{};
    std::array<std::size_t, 64U> frequencies{};
    std::size_t distinct = 0U;
    std::size_t maximum_frequency = 0U;
    std::size_t longest_run = 0U;
    std::size_t current_run = 0U;
    std::uint8_t previous = 0U;

    for (std::size_t index = 0U; index < value.size(); ++index) {
        const std::uint8_t encoded = detail::base64url_value(value[index]);
        if (encoded == 0xFFU) {
            return SharedSecretValidationError::InvalidCharacter;
        }
        encoded_values[index] = encoded;
        if (frequencies[encoded]++ == 0U) ++distinct;
        if (frequencies[encoded] > maximum_frequency) {
            maximum_frequency = frequencies[encoded];
        }
        if (index != 0U && value[index] == previous) {
            ++current_run;
        } else {
            current_run = 1U;
            previous = value[index];
        }
        if (current_run > longest_run) longest_run = current_run;
    }

    // Thirty-two input bytes leave four significant bits in the 43rd symbol;
    // the two unused low bits must be zero in a canonical encoding.
    if ((detail::base64url_value(value.back()) & 0x03U) != 0U) {
        return SharedSecretValidationError::NonCanonicalEncoding;
    }

    if (distinct < 16U || maximum_frequency > 8U || longest_run > 4U) {
        return SharedSecretValidationError::ObviousLowEntropyPattern;
    }
    for (std::size_t period = 1U; period <= 16U; ++period) {
        bool periodic = true;
        for (std::size_t index = period; index < value.size(); ++index) {
            if (value[index] != value[index % period]) {
                periodic = false;
                break;
            }
        }
        if (periodic) {
            return SharedSecretValidationError::ObviousLowEntropyPattern;
        }
    }

    std::array<std::uint8_t, kSharedSecretBytes> decoded{};
    std::size_t output_index = 0U;
    std::uint32_t accumulator = 0U;
    unsigned int available_bits = 0U;
    for (const std::uint8_t encoded : encoded_values) {
        accumulator = static_cast<std::uint32_t>(
            (accumulator << 6U) | encoded);
        available_bits += 6U;
        if (available_bits >= 8U) {
            available_bits -= 8U;
            decoded[output_index++] = static_cast<std::uint8_t>(
                accumulator >> available_bits);
            accumulator &= available_bits == 0U
                ? 0U
                : static_cast<std::uint32_t>((1U << available_bits) - 1U);
        }
    }
    if (output_index != decoded.size()) {
        return SharedSecretValidationError::NonCanonicalEncoding;
    }

    std::array<std::size_t, 256U> byte_frequencies{};
    std::size_t distinct_bytes = 0U;
    std::size_t maximum_byte_frequency = 0U;
    for (const std::uint8_t byte : decoded) {
        if (byte_frequencies[byte]++ == 0U) ++distinct_bytes;
        maximum_byte_frequency = (std::max)(
            maximum_byte_frequency, byte_frequencies[byte]);
    }
    if (distinct_bytes < 16U || maximum_byte_frequency > 4U) {
        return SharedSecretValidationError::ObviousLowEntropyPattern;
    }
    for (std::size_t period = 1U; period <= 16U; ++period) {
        bool periodic = true;
        for (std::size_t index = period; index < decoded.size(); ++index) {
            if (decoded[index] != decoded[index % period]) {
                periodic = false;
                break;
            }
        }
        if (periodic) {
            return SharedSecretValidationError::ObviousLowEntropyPattern;
        }
    }

    const std::uint8_t byte_delta = static_cast<std::uint8_t>(
        decoded[1] - decoded[0]);
    bool arithmetic_sequence = true;
    for (std::size_t index = 2U; index < decoded.size(); ++index) {
        if (static_cast<std::uint8_t>(decoded[index] - decoded[index - 1U]) !=
            byte_delta) {
            arithmetic_sequence = false;
            break;
        }
    }
    if (arithmetic_sequence) {
        return SharedSecretValidationError::ObviousLowEntropyPattern;
    }
    return SharedSecretValidationError::None;
}

[[nodiscard]] inline SharedSecretValidationError validate_shared_secret(
    const std::string_view value) noexcept {
    return validate_shared_secret(std::span<const std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(value.data()), value.size()});
}

[[nodiscard]] inline bool is_valid_shared_secret(
    const std::span<const std::uint8_t> value) noexcept {
    return validate_shared_secret(value) == SharedSecretValidationError::None;
}

[[nodiscard]] inline bool is_valid_shared_secret(
    const std::string_view value) noexcept {
    return validate_shared_secret(value) == SharedSecretValidationError::None;
}

[[nodiscard]] inline std::string_view shared_secret_validation_message(
    const SharedSecretValidationError error) noexcept {
    switch (error) {
        case SharedSecretValidationError::None:
            return "";
        case SharedSecretValidationError::WrongLength:
            return "The shared key must be exactly 43 characters (a generated 256-bit key).";
        case SharedSecretValidationError::InvalidCharacter:
            return "The shared key may contain only base64url letters, digits, '-' and '_'.";
        case SharedSecretValidationError::NonCanonicalEncoding:
            return "The shared key is not a canonical 32-byte base64url value.";
        case SharedSecretValidationError::ObviousLowEntropyPattern:
            return "The shared key looks hand-authored or repetitive; generate a fresh 256-bit key.";
    }
    return "The shared key is invalid.";
}

inline void require_valid_shared_secret(
    const std::span<const std::uint8_t> value) {
    const auto error = validate_shared_secret(value);
    if (error != SharedSecretValidationError::None) {
        throw std::invalid_argument(
            std::string{shared_secret_validation_message(error)});
    }
}

inline void require_valid_shared_secret(const std::string_view value) {
    const auto error = validate_shared_secret(value);
    if (error != SharedSecretValidationError::None) {
        throw std::invalid_argument(
            std::string{shared_secret_validation_message(error)});
    }
}

} // namespace secure
