<script lang="ts">
    import NDK, {
        NDKEvent,
        NDKPrivateKeySigner,
        NDKSubscription,
        NDKUser
    } from "@nostr-dev-kit/ndk";
    import { Conversation } from "$lib/conversation";
    import { bytesToHex } from "@noble/hashes/utils";
    import { schnorr } from "@noble/curves/secp256k1";
    import { sha256 } from "@noble/hashes/sha256";
    import UserChat from "$lib/components/UserChat.svelte";

    const utf8Encoder = new TextEncoder();

    const relays = ["ws://localhost:8080"];

    let alice: NDKUser | null;
    let aliceNdk = new NDK({ explicitRelayUrls: relays });
    let aliceIdSigner: NDKPrivateKeySigner | null;
    let alicePrekeySigner: NDKPrivateKeySigner | null;
    let alicePrekey: NDKEvent | null;
    let aliceGWSub: NDKSubscription | null;

    let bob: NDKUser | null;
    let bobNdk = new NDK({ explicitRelayUrls: relays });
    let bobIdSigner: NDKPrivateKeySigner | null;
    let bobPrekeySigner: NDKPrivateKeySigner | null;
    let bobPrekey: NDKEvent | null;
    let bobGWSub: NDKSubscription | null;

    let conversationRequestSent = false;
    let conversationRequestRecieved = false;
    let receivedConversationRequest: NDKEvent | null = null;

    let initialRootKey: string | null = null;
    let haveStarted = false;

    /**
     * Generate all the keys, signers, and events needed to start fresh
     */
    async function setup(): Promise<void> {
        // Do nothing if we have already started
        if (haveStarted) return;
        console.log("🏗️ Setting up...");
        await setupAlice();
        await setupBob();
        haveStarted = true;
        console.log("✅ Setup complete");
    }

    async function setupAlice(): Promise<void> {
        // This is Alice's identity key and signer
        aliceIdSigner = NDKPrivateKeySigner.generate();
        aliceNdk.signer = aliceIdSigner;
        await aliceNdk.connect().then(() => console.log("Alice NDK connected"));
        alice = aliceNdk.getUser({ pubkey: (await aliceIdSigner.user()).pubkey });
        // This is Alice's prekey key and signer
        alicePrekeySigner = NDKPrivateKeySigner.generate();
        aliceNdk.signer = aliceIdSigner;

        // Create a kind:0 for Alice
        const aliceProfile = {
            display_name: "Alice",
            picture: "https://api.dicebear.com/8.x/lorelei/svg"
        };

        const aliceKind0 = new NDKEvent(aliceNdk, {
            kind: 0,
            created_at: Math.floor(Date.now() / 1000),
            content: JSON.stringify(aliceProfile),
            pubkey: (await aliceIdSigner.user()).pubkey,
            tags: []
        });

        await aliceKind0.publish();
        console.log("Alice's kind:0 published");

        const alicePrekeyPubkey = (await alicePrekeySigner.user()).pubkey;

        const preKeySig = bytesToHex(
            schnorr.sign(
                bytesToHex(sha256(utf8Encoder.encode(alicePrekeyPubkey))),
                alicePrekeySigner.privateKey!
            )
        );

        // This is Alices's prekey event
        alicePrekey = new NDKEvent(aliceNdk, {
            kind: 10443,
            created_at: Math.floor(Date.now() / 1000),
            pubkey: (await aliceIdSigner.user()).pubkey,
            content: alicePrekeyPubkey,
            tags: [["prekey_sig", preKeySig]]
        });

        // Sign and publish the prekey with Alice's normal key
        await alicePrekey.publish();
        console.log("Alice's prekey published");
    }

    async function setupBob(): Promise<void> {
        // This is Bob's identity key and signer
        bobIdSigner = NDKPrivateKeySigner.generate();
        bobNdk.signer = bobIdSigner;
        await bobNdk.connect().then(() => console.log("Bob NDK connected"));
        bob = bobNdk.getUser({ pubkey: (await bobIdSigner.user()).pubkey });
        // This is Bob's prekey key and signer
        bobPrekeySigner = NDKPrivateKeySigner.generate();
        bobNdk.signer = bobIdSigner;

        // Create a kind:0 for Bob
        const bobProfile = {
            display_name: "Bob",
            picture: "https://api.dicebear.com/8.x/pixel-art/svg"
        };

        const bobKind0 = new NDKEvent(bobNdk, {
            kind: 0,
            created_at: Math.floor(Date.now() / 1000),
            content: JSON.stringify(bobProfile),
            pubkey: (await bobIdSigner.user()).pubkey,
            tags: []
        });

        await bobKind0.publish();
        console.log("Bob's kind:0 published");

        const bobPrekeyPubkey = (await bobPrekeySigner.user()).pubkey;

        const preKeySig = bytesToHex(
            schnorr.sign(
                bytesToHex(sha256(utf8Encoder.encode(bobPrekeyPubkey))),
                bobPrekeySigner.privateKey!
            )
        );

        // This is Bob's prekey event
        bobPrekey = new NDKEvent(bobNdk, {
            kind: 10443,
            created_at: Math.floor(Date.now() / 1000),
            pubkey: (await bobIdSigner.user()).pubkey,
            content: bobPrekeyPubkey,
            tags: [["prekey_sig", preKeySig]]
        });

        // Sign and publish the prekey with Bob's normal key

        await bobPrekey.publish();
        console.log("Bob's prekey published");
    }

    /**
     * Reset all keys and signers
     * */
    function reset(): void {
        if (confirm("Are you sure you want to reset everything?")) {
            console.log("🔥 Burn it all down!");

            aliceNdk.signer = undefined;
            alice = null;
            aliceIdSigner = null;
            alicePrekeySigner = null;
            alicePrekey = null;
            aliceGWSub?.stop();
            aliceGWSub = null;

            bobNdk.signer = undefined;
            bob = null;
            bobIdSigner = null;
            bobPrekeySigner = null;
            bobPrekey = null;
            haveStarted = false;
            bobGWSub?.stop();
            bobGWSub = null;

            conversationRequestRecieved = false;
            receivedConversationRequest = null;
            conversationRequestSent = false;
            initialRootKey = null;

            console.log("✅ Reset complete");
        }
    }

    /**
     * Send a conversation request to a user
     * This does the initial ECDH key exchange and sends the conversation request event
     * */
    async function sendConversationRequest(event: CustomEvent) {
        console.log(event.detail);
        const { ndk, sender, recipient } = event.detail;
        console.log("📨 Sending conversation request...");
        const conversation = new Conversation(
            ndk,
            sender,
            sender.ndk?.signer as NDKPrivateKeySigner,
            recipient
        );
        await conversation.initConversation().then(() => {
            initialRootKey = conversation.hexRootKey();
            console.log("🔑 ECDH key exchange complete");
        });
    }

    /**
     * This sends a message to the conversation with the given message
     * A conversation is an instance of a conversation between two users
     * The conversation is created when the conversation request is accepted
     * Conversations have a shared secret and multiple ratchet chains that must be
     * persisted and updated over time. This will get abstracted out in NDK. For now,
     * we'll use a simple in-memory object.
     * @param conversation
     * @param message
     */
    function sendMessage(conversation: Conversation, message: string) {}
</script>

<div>
    {#if haveStarted}
        <button on:click={reset}>Reset everything</button>

        <div class="flex flex-row gap-8 my-10">
            <UserChat
                ndk={aliceNdk}
                user={alice}
                otherUser={bob}
                prekey={alicePrekey}
                prekeySigner={alicePrekeySigner}
                bind:conversationRequestSent
                bind:initialRootKey
                on:sendConversationRequest={sendConversationRequest}
            />
            <UserChat
                ndk={bobNdk}
                user={bob}
                otherUser={alice}
                prekey={bobPrekey}
                prekeySigner={bobPrekeySigner}
                bind:conversationRequestSent
                bind:initialRootKey
                on:sendConversationRequest={sendConversationRequest}
            />
        </div>
        <!-- <form>
            <div class="flex flex-col gap-2">
                <label for="message">Message</label>
                <textarea placeholder="Enter your message" id="message" class="border rounded-md"
                ></textarea>
            </div>
        </form> -->
    {:else}
        <p>
            First, we'll generate Alice and Bob as new users with some basic profile data and a
            prekey event (<span class="font-mono">kind:10443</span>) published.
        </p>
        <p>Open your browser console to see messages about what is happening.</p>
        <button on:click={setup}>Let's Go</button>
    {/if}
</div>