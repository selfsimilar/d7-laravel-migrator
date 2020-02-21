<?php

namespace App\Services;

class LegacyPassword
{

    public static function match(string $plain, string $hashed)
    {
        // We imported users from Drupal 7 site, so take code from D7 function
        // _password_crypt() to perform legacy hash. Specifically, the
        // algorithm, number of hash rounds, and salt are encoded in the first
        // 12 characters of the hash.
        // https://api.drupal.org/api/drupal/includes%21password.inc/7.x

        // The first 12 characters of an existing hash are its setting string.
        $setting = substr($hashed, 0, 12);
        if ($setting[0] != '$' || $setting[2] != '$') {
            return FALSE;
        }
        $count_log2 = strpos('./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', $setting[3]);

        if ($count_log2 < 7 || $count_log2 > 30) {
            return FALSE;
        }
        $salt = substr($setting, 4, 8);

        if (strlen($salt) != 8) {
            return FALSE;
        }
        $count = 1 << $count_log2;

        // All our users have pwd hashes starting with '$S$', signifying sha512.
        $hash = hash('sha512', $salt . $plain, TRUE);
        do {
            $hash = hash('sha512', $hash . $plain, TRUE);
        } while (--$count);
        $len = strlen($hash);
        $legacy = $setting . self::passwordBase64Encode($hash, $len);

        return substr($legacy, 0, 55) === $hashed;
    }

    /**
     * Encodes bytes into printable base 64 using the *nix standard from crypt().
     *
     * @param $input
     *   The string containing bytes to encode.
     * @param $count
     *   The number of characters (bytes) to encode.
     *
     * @return
     *   Encoded string
     */
    private static function passwordBase64Encode($input, $count) {
        $output = '';
        $i = 0;
        $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        do {
            $value = ord($input[$i++]);
            $output .= $itoa64[$value & 0x3f];
            if ($i < $count) {
                $value |= ord($input[$i]) << 8;
            }
            $output .= $itoa64[$value >> 6 & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            if ($i < $count) {
                $value |= ord($input[$i]) << 16;
            }
            $output .= $itoa64[$value >> 12 & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            $output .= $itoa64[$value >> 18 & 0x3f];
        } while ($i < $count);
        return $output;
    }
}