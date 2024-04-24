import { type NDKUser, NDKEvent, NDKPrivateKeySigner } from "@nostr-dev-kit/ndk";
import NDK from "@nostr-dev-kit/ndk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { giftWrap } from "./giftWrap";
import { extract as hkdf_extract, expand as hkdf_expand } from "@noble/hashes/hkdf";
import { turnDhRatchet, turnSymmetricRatchet } from "./symmetricalRatchet";
import { nip44 } from "nostr-tools";

export const utf8Encoder: TextEncoder = new TextEncoder();

// We need a way to instantiate this from nothing but also to load from storage.

/**
 * Represents a double ratchet DM conversation between two users.
 * Will eventually become NDKEncryptedConversation.
 */
export class Conversation {
    public ndk: NDK;
    public sender: NDKUser;
    public receiver: NDKUser;
    private _senderSigner: NDKPrivateKeySigner;
    private DHSendingKeypair: { privateKey?: Uint8Array; publicKey?: Uint8Array } = {};
    private DHReceivingPubkey?: Uint8Array;
    private secretKey?: Uint8Array;
    private rootKey?: Uint8Array;
    private chainKeySending?: Uint8Array;
    private chainKeyReceiving?: Uint8Array;
    private sendingChainMessageCount: number = 0;
    private receivingChainMessageCount: number = 0;
    private previousSendingChainMessageCount: number = 0;
    private mkSkipped: Map<{ ratchetPubkey: Uint8Array; messageNumber: number }, Uint8Array> =
        new Map();

    MAX_SKIP = 100;
    INITIAL_RATCHET_INPUT = "nostr";

    // How do we track chain and message keys?
    // How do we store decrypted messages?
    // Need to store encrypted messages that arrive out of order.

    // Need to have
    // fingerprinting for offline verification
    // methods for ratcheting where needed
    // methods for storing keys and handling out of order messages
    // methods for handling message encryption and decryption
    // methods for handling message signing and verification

    constructor(ndk: NDK, sender: NDKUser, senderSigner: NDKPrivateKeySigner, receiver: NDKUser) {
        this.ndk = ndk;
        this.sender = sender;
        this.receiver = receiver;

        // For this demo we only allow PK signer
        // This is the senders nostr identity key signer
        this._senderSigner = senderSigner;
    }

    get senderSigner() {
        return this._senderSigner;
    }

    set senderSigner(signer: NDKPrivateKeySigner) {
        this._senderSigner = signer;
    }

    public async initConversation(message?: string) {
        // Check we have a signer for the sender
        if (!this.senderSigner.privateKey) throw new Error("Sender private key not set");

        // Fetch the receiver's prekey bundle
        const prekey = await this.fetchAndValidatePrekey();
        if (!prekey) throw new Error("Invalid or Missing Recipient Prekey");

        // Generate an ephemeral keypair for the sender to use in the DH exchange
        this.DHSendingKeypair.privateKey = schnorr.utils.randomPrivateKey();
        this.DHSendingKeypair.publicKey = schnorr.getPublicKey(this.DHSendingKeypair.privateKey);

        // Set the recipients's pubkey as the initial DHReceivingPubkey
        this.DHReceivingPubkey = hexToBytes(this.receiver.pubkey);

        // Calculate the shared root key (DH the various pairs and then concat and hash)
        let DH1: Uint8Array | null = secp256k1
            .getSharedSecret(this.senderSigner.privateKey, "02" + prekey.content)
            .subarray(1, 33);
        let DH2: Uint8Array | null = secp256k1
            .getSharedSecret(this.DHSendingKeypair.privateKey, "02" + this.receiver.pubkey)
            .subarray(1, 33);
        let DH3: Uint8Array | null = secp256k1
            .getSharedSecret(this.DHSendingKeypair.privateKey, "02" + prekey.content)
            .subarray(1, 33);
        let combinedDH: Uint8Array | null = new Uint8Array(DH1.length + DH2.length + DH3.length);
        combinedDH.set(DH1, 0);
        combinedDH.set(DH2, DH1.length);
        combinedDH.set(DH3, DH1.length + DH2.length);

        // Set initial secret key
        this.secretKey = hkdf_extract(sha256, combinedDH, "salt");

        // Do initial DH ratchet
        const ratchetOut = turnDhRatchet(this.secretKey, DH2);
        this.rootKey = ratchetOut.rootKey;
        this.chainKeySending = ratchetOut.chainKey;

        // // Delete (as securely as we can in JS) the ephemeral private key and all the DH outputs
        DH1 = null;
        DH2 = null;
        DH3 = null;
        combinedDH = null;
        this.DHSendingKeypair.privateKey = undefined;

        // ✅ Create conversation request event
        // DON'T SIGN IT. We're going to gift-wrap it.
        const messageContent = message || "Hey, let's start a conversation!";
        const symmetricRatchetOut = turnSymmetricRatchet(this.chainKeySending);
        this.chainKeySending = symmetricRatchetOut.chainKey;
        const encryptedMessage = nip44.v2.encrypt(messageContent, symmetricRatchetOut.messageKey!);

        // ==========================================================
        // TODO: This might need to happen after we set up the event
        this.sendingChainMessageCount++;
        // ==========================================================

        const conversationRequest = new NDKEvent(this.ndk, {
            kind: 443,
            created_at: Math.floor(Date.now() / 1000),
            pubkey: this.sender.pubkey,
            content: encryptedMessage,
            tags: [
                ["p", this.receiver.pubkey],
                ["prekey", prekey.content],
                ["ephemeral", bytesToHex(this.DHSendingKeypair.publicKey)]
            ]
        });

        // ✅ Gift-wrap the conversation request event
        const wrapEvent = await giftWrap(
            this.ndk,
            conversationRequest,
            this.receiver.pubkey,
            this.senderSigner
        );

        // Publish the gift-wrapped conversation request
        // TODO: Publish ONLY to recipient's read relays that support AUTH
        await wrapEvent.publish();
    }

    public sendMessage(message: string) {
        // Encrypt the message with the current sending chain key
        // Create a new DRDM kind 444 event & GW it & publish it
    }

    // TODO: This will need better error handling
    public async handleConversationRequest(
        event: NDKEvent,
        prekeySigner: NDKPrivateKeySigner
    ): Promise<string> {
        const senderPubkey = event.pubkey;
        const ephemeralPubkey = event.getMatchingTags("ephemeral")[0][1];
        const prekey = event.getMatchingTags("prekey")[0][1];

        if ((await prekeySigner.user()).pubkey !== prekey) throw new Error("Prekeys don't match");

        // Calculate the shared root key (DH the various pairs and then concat and hash)
        let DH1: Uint8Array | null = secp256k1
            .getSharedSecret(prekeySigner.privateKey!, "02" + senderPubkey)
            .subarray(1, 33);
        let DH2: Uint8Array | null = secp256k1
            .getSharedSecret(this.senderSigner.privateKey!, "02" + ephemeralPubkey)
            .subarray(1, 33);
        let DH3: Uint8Array | null = secp256k1
            .getSharedSecret(prekeySigner.privateKey!, "02" + ephemeralPubkey)
            .subarray(1, 33);
        let combinedDH: Uint8Array | null = new Uint8Array(DH1.length + DH2.length + DH3.length);
        combinedDH.set(DH1, 0);
        combinedDH.set(DH2, DH1.length);
        combinedDH.set(DH3, DH1.length + DH2.length);

        // Set initial secret key
        this.secretKey = hkdf_extract(sha256, combinedDH, "salt");

        // Do initial DH ratchet
        const ratchetOut = turnDhRatchet(this.secretKey, DH2);
        this.rootKey = ratchetOut.rootKey;
        this.chainKeyReceiving = ratchetOut.chainKey;

        // Do initial symmetric ratchet
        const symmetricRatchetOut = turnSymmetricRatchet(this.chainKeyReceiving);
        this.chainKeySending = symmetricRatchetOut.chainKey;

        // TODO: Need to handle counts and skipped messages
        const decryptedMessage = nip44.v2.decrypt(event.content, symmetricRatchetOut.messageKey!);
        console.log("🔓 Decrypted Message", decryptedMessage);

        // Delete (as securely as we can in JS) the DH outputs
        DH1 = null;
        DH2 = null;
        DH3 = null;
        combinedDH = null;
        // TODO: What else to delete??

        return decryptedMessage;
    }

    public handleIncomingMessage() {}

    public secretKeySet(): boolean {
        return this.secretKey !== undefined;
    }

    public hexSecretKey(): string {
        if (!this.secretKey) throw new Error("Secret key not set");
        return bytesToHex(this.secretKey);
    }

    private async fetchAndValidatePrekey(): Promise<NDKEvent | null> {
        // NDK validates the signature of this event
        const prekey = await this.ndk.fetchEvent({
            authors: [this.receiver.pubkey],
            kinds: [10443 as number]
        });

        // No prekey? Can't start a conversation.
        if (!prekey) return null;
        const tags = prekey.getMatchingTags("prekey_sig");

        // No tags? Invalid prekey.
        if (tags.length === 0) return null;
        const hashedPubkey = bytesToHex(sha256(utf8Encoder.encode(prekey.content)));

        // Invalid prekey signature? Invalid prekey.
        // TODO: Need to further verify format of event.content, prekey_sig tag value, etc.
        const valid = schnorr.verify(tags[0][1], hashedPubkey, prekey.content);
        if (!valid) return null;

        return prekey;
    }
}
