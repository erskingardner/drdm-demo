import { type NDKUser, NDKEvent, NDKPrivateKeySigner } from "@nostr-dev-kit/ndk";
import NDK from "@nostr-dev-kit/ndk";
import { bytesToHex } from "@noble/hashes/utils";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { giftWrap } from "./giftWrap";
import { extract as hkdf_extract, expand as hkdf_expand } from "@noble/hashes/hkdf";

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
    public senderSigner: NDKPrivateKeySigner;
    private DHSendingKeypair: { privateKey?: Uint8Array; publicKey?: Uint8Array } = {};
    private DHReceivingPubkey?: Uint8Array;
    private rootKey?: Uint8Array;
    private chainKeySending?: Uint8Array;
    private chainKeyReceiving?: Uint8Array;
    private sendingChainMessageCount: number = 0;
    private receivingChainMessageCount: number = 0;
    private previousSendingChainMessageCount: number = 0;
    private mkSkipped: Map<{ ratchetPubkey: Uint8Array; messageNumber: number }, Uint8Array> =
        new Map();

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
        this.senderSigner = senderSigner;
    }

    public async initConversation(message?: string) {
        console.log("Initializing conversation request...");
        // Check we have a signer for the sender
        if (!this.senderSigner.privateKey) throw new Error("Sender private key not set");

        // Fetch the receiver's prekey bundle
        const prekey = await this.fetchAndValidatePrekey();
        if (!prekey) throw new Error("Invalid or Missing Recipient Prekey");

        // Generate an ephemeral keypair for the sender to use in the DH exchange
        this.DHSendingKeypair.privateKey = schnorr.utils.randomPrivateKey();
        this.DHSendingKeypair.publicKey = schnorr.getPublicKey(this.DHSendingKeypair.privateKey);

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
        this.rootKey = hkdf_extract(sha256, combinedDH, "salt");

        console.log("DH1", bytesToHex(DH1));
        console.log("DH2", bytesToHex(DH2));
        console.log("DH3", bytesToHex(DH3));
        console.log("combinedDH", bytesToHex(combinedDH));
        console.log("rootKey", bytesToHex(this.rootKey));

        // // Delete (as securely as we can in JS) the ephemeral private key and all the DH outputs
        DH1 = null;
        DH2 = null;
        DH3 = null;
        combinedDH = null;
        this.DHSendingKeypair.privateKey = undefined;

        // ✅ Create conversation request event
        // DON'T SIGN IT. We're going to gift-wrap it.
        const messageContent = message || "Hey, let's start a conversation!";
        const encryptedMessage = "TODO: encrypt messageContent with double ratchet, not NIP-44";

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

        console.log(
            "Conversation Request Event (rumor, doesn't get published)\n",
            conversationRequest.rawEvent()
        );

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
        console.log("Gift Wrap Event Published\n", wrapEvent.rawEvent());
    }

    public sendMessage(message: string) {
        // Encrypt the message with the current sending chain key
        // Create a new DRDM kind 444 event & GW it & publish it
    }

    public async handleConversationRequest(event: NDKEvent, prekeySigner: NDKPrivateKeySigner) {
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
        this.rootKey = hkdf_extract(sha256, combinedDH, "salt");

        console.log("DH1 Receiver", bytesToHex(DH1));
        console.log("DH2 Receiver", bytesToHex(DH2));
        console.log("DH3 Receiver", bytesToHex(DH3));
        console.log("combinedDH Receiver", bytesToHex(combinedDH));
        console.log("rootKey Receiver", bytesToHex(this.rootKey));

        // Delete (as securely as we can in JS) the ephemeral private key and all the DH outputs
        // Generate the shared chain key
    }

    public handleIncomingMessage() {}

    public rootKeySet(): boolean {
        return this.rootKey !== undefined;
    }

    public hexRootKey(): string {
        if (!this.rootKey) throw new Error("Root key not set");
        return bytesToHex(this.rootKey);
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

    private ratchetEncrypt(plaintext: string): string {
        // ratchet the root and chain keys
    }
}
