import { type NDKUser, NDKEvent, NDKPrivateKeySigner, NDKRelay } from "@nostr-dev-kit/ndk";
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
        this.generateDHKeypair();

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
        this.sendingChainMessageCount++;
        const encryptedMessage = nip44.v2.encrypt(messageContent, symmetricRatchetOut.messageKey!);

        const conversationRequest = new NDKEvent(this.ndk, {
            kind: 443,
            created_at: Math.floor(Date.now() / 1000),
            pubkey: this.sender.pubkey,
            content: encryptedMessage,
            tags: [
                ["p", this.receiver.pubkey],
                ["prekey", prekey.content],
                ["ephemeral", bytesToHex(this.DHSendingKeypair.publicKey!)]
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

    // TODO: This will need better error handling
    // We'll only know it's no good if we can't decrypt the message
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
        console.log("🔓 Successfully Decrypted Conversation Request Message: ", decryptedMessage);

        // Delete (as securely as we can in JS) the DH outputs
        DH1 = null;
        DH2 = null;
        DH3 = null;
        combinedDH = null;
        // TODO: What else to delete??

        return decryptedMessage;
    }

    public async sendMessage(message: string): Promise<Set<NDKRelay>> {
        // Check we have a signer for the sender
        if (!this.senderSigner.privateKey) throw new Error("Sender private key not set");
        if (!this.DHSendingKeypair.publicKey) this.generateDHKeypair();
        const encryptedMessage = this.ratchetEncrypt(message);
        const event = new NDKEvent(this.ndk, {
            kind: 444,
            created_at: Math.floor(Date.now() / 1000),
            pubkey: this.sender.pubkey,
            content: encryptedMessage,
            tags: [
                ["p", this.receiver.pubkey],
                ["dh_sending", bytesToHex(this.DHSendingKeypair.publicKey!)],
                ["current_index", this.sendingChainMessageCount.toString()],
                ["previous_length", this.previousSendingChainMessageCount.toString()]
            ]
        });

        const wrapEvent = await giftWrap(this.ndk, event, this.receiver.pubkey, this.senderSigner);
        return await wrapEvent.publish();
    }

    public handleIncomingMessage(event: NDKEvent): NDKEvent | void {
        // Check event tags
        if (event.getMatchingTags("dh_sending").length === 0)
            throw new Error("Missing public key for decryption");
        if (event.getMatchingTags("current_index").length === 0)
            throw new Error("Missing current index for decryption");
        if (event.getMatchingTags("previous_length").length === 0)
            throw new Error("Missing previous index for decryption");

        // Ratchet as needed, store message if missed, return decrypted message in the event
        return this.ratchetDecrypt(event);
    }

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

    /**
     * Generates a Diffie-Hellman key pair for the conversation.
     * The private key is randomly generated, and the public key is derived from the private key.
     */
    private generateDHKeypair() {
        this.DHSendingKeypair.privateKey = schnorr.utils.randomPrivateKey();
        this.DHSendingKeypair.publicKey = schnorr.getPublicKey(this.DHSendingKeypair.privateKey);
    }

    private ratchetEncrypt(message: string): string {
        // We only do a symmetric ratchet here because we'll do a DH ratchet
        // each time we see a new message from the other party.
        const symmetricRatchetOut = turnSymmetricRatchet(this.chainKeySending!);
        this.sendingChainMessageCount++;
        this.chainKeySending = symmetricRatchetOut.chainKey;

        // Encrypt the message
        return nip44.v2.encrypt(message, symmetricRatchetOut.messageKey!);
    }

    /**
     * TODO: NOT SURE IF THIS WORKS YET
     * @param event
     * @returns
     */
    private ratchetDecrypt(event: NDKEvent): NDKEvent {
        // If we have the message key already, decrypt it and return it
        let decryptedEvent: NDKEvent | null = this.trySkippedMessages(event);
        if (decryptedEvent !== null) return decryptedEvent;

        // If we have a new DH key, we need to ratchet first
        // Preserving the state of our current message chain
        const dhKey = event.getMatchingTags("dh_sending")[0][1];
        if (dhKey === undefined) throw new Error("Missing DH key for decryption");

        if (hexToBytes(dhKey) !== this.DHReceivingPubkey) {
            this.skipMessageKeys(event);
            this.previousSendingChainMessageCount = this.sendingChainMessageCount;
            this.sendingChainMessageCount = 0;
            this.receivingChainMessageCount = 0;
            this.DHReceivingPubkey = hexToBytes(dhKey);

            const newDH = secp256k1
                .getSharedSecret(this.DHSendingKeypair.privateKey!, "02" + dhKey)
                .subarray(1, 33);
            const ratchetOut = turnDhRatchet(this.rootKey!, newDH);
            this.rootKey = ratchetOut.rootKey;
            this.chainKeyReceiving = ratchetOut.chainKey;
            this.generateDHKeypair();
            const newNewDH = secp256k1
                .getSharedSecret(
                    this.DHSendingKeypair.privateKey!,
                    "02" + bytesToHex(this.DHReceivingPubkey)
                )
                .subarray(1, 33);
            const newRatchetOut = turnDhRatchet(this.rootKey!, newNewDH);
            this.rootKey = newRatchetOut.rootKey;
            this.chainKeySending = newRatchetOut.chainKey;
        }
        this.skipMessageKeys(event);
        const symmetricRatchetOut = turnSymmetricRatchet(this.chainKeyReceiving!);
        this.chainKeyReceiving = symmetricRatchetOut.chainKey;
        this.receivingChainMessageCount++;
        event.content = nip44.v2.decrypt(event.content, symmetricRatchetOut.messageKey!);
        return event;
    }

    /**
     * Tries to decrypt skipped messages in the conversation.
     *
     * @param event - The NDKEvent object representing the current event.
     * @returns The decrypted NDKEvent object if a skipped message is successfully decrypted, otherwise null.
     */
    private trySkippedMessages(event: NDKEvent): NDKEvent | null {
        if (this.mkSkipped.size === 0) return null;
        let decryptedEvent: NDKEvent | null = null;
        const dhKey = event.getMatchingTags("dh_sending")[0][1];
        const currentMessageNumber = parseInt(event.getMatchingTags("current_index")[0][1]);
        const key = {
            ratchetPubkey: hexToBytes(dhKey),
            messageNumber: currentMessageNumber
        };
        if (this.mkSkipped.has(key)) {
            const mk = this.mkSkipped.get(key);
            this.mkSkipped.delete(key);
            const decryptedMessage = nip44.v2.decrypt(event.content, mk!);
            event.content = decryptedMessage;
            decryptedEvent = event;
        }
        return decryptedEvent;
    }

    /**
     * Skips and stores message keys based on the provided event.
     * @param event - The NDKEvent object containing information about the event.
     */
    private skipMessageKeys(event: NDKEvent): void {
        const currentMessageNumber = parseInt(event.getMatchingTags("current_index")[0][1]);
        const prevLength = event.getMatchingTags("previous_length")[0][1];

        // Bail early if we've hit our skip limit
        if (this.receivingChainMessageCount + this.MAX_SKIP < parseInt(prevLength)) return;
        if (this.chainKeyReceiving) {
            while (this.receivingChainMessageCount < currentMessageNumber) {
                const symRatchetOut = turnSymmetricRatchet(this.chainKeyReceiving);
                this.mkSkipped.set(
                    {
                        ratchetPubkey: this.DHReceivingPubkey!,
                        messageNumber: this.receivingChainMessageCount
                    },
                    symRatchetOut.messageKey!
                );
                this.receivingChainMessageCount++;
            }
        }
    }
}
