import { expand as hkdf_expand } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

const INPUT_CONSTANT = "nostr";

type RatchetOutput = {
    rootKey?: Uint8Array;
    chainKey: Uint8Array;
    messageKey?: Uint8Array;
};

/**
 * Turns the symmetrical ratchet to generate a new chain key and message key
 * based on the previous chain key.
 *
 * Each user in a conversation has a sending and receiving chain that will be
 * ratcheted each time a message is sent.
 *
 * @param prevChainKey The previous chain key used as input for the ratchet.
 * @returns An object containing the new chain key and message key.
 */
export function turnSymmetricRatchet(prevChainKey: Uint8Array): RatchetOutput {
    const expanded = hkdf_expand(sha256, prevChainKey, INPUT_CONSTANT, 64);
    return {
        chainKey: expanded.subarray(0, 32),
        messageKey: expanded.subarray(32)
    };
}

/**
 * Turns the Diffie-Hellman (DH) ratchet by deriving new keys from the previous
 * root key and the DH result of the most recent key pairs.
 *
 * @param prevRootKey - The previous root key used in the ratchet.
 * @param dhResult - The Diffie-Hellman (DH) result used to derive new keys.
 * @returns An object containing the new root key and a new chain key.
 */
export function turnDhRatchet(prevRootKey: Uint8Array, dhResult: Uint8Array): RatchetOutput {
    const expanded = hkdf_expand(sha256, prevRootKey, dhResult, 64);
    return {
        rootKey: expanded.subarray(0, 32),
        chainKey: expanded.subarray(32, 64)
    };
}
