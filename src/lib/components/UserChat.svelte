<script lang="ts">
    import type NDK from "@nostr-dev-kit/ndk";
    import type { NDKUser, NDKEvent, NDKPrivateKeySigner } from "@nostr-dev-kit/ndk";
    import { Avatar, Name } from "@nostr-dev-kit/ndk-svelte-components";
    import { createEventDispatcher, onMount } from "svelte";
    import { unwrap } from "$lib/giftWrap";
    import { Conversation } from "$lib/conversation";

    const dispatch = createEventDispatcher();

    export let ndk: NDK;
    export let user: NDKUser;
    export let otherUser: NDKUser;
    export let prekey: NDKEvent;

    // In reality you wouldn't be passing this in like this – it would be managed on the client in a secure way.
    export let prekeySigner: NDKPrivateKeySigner;

    export let conversationRequestSent: boolean;
    export let initialSecretKey: string | null;

    let sentConversationRequest = false;
    let receivedConversationRequest = false;
    let conversationRequest: NDKEvent | null = null;
    let decryptedConversationRequestMessage: string | null = null;
    let showPrekeyEventBlock = false;
    let showConversationEventBlock = false;
    let conversation: Conversation | null = null;
    let receiverSecretKey: string;

    let conversationAccepted = false;

    let giftWrapSub = ndk.subscribe({ kinds: [1059 as number], "#p": [user.pubkey] });
    giftWrapSub.on("event", async (event) => {
        const unwrapped = unwrap(ndk, event, ndk.signer! as NDKPrivateKeySigner);
        if (unwrapped.kind === 443) {
            conversationRequest = unwrapped;
            console.log("📬 Received a conversation request");
            receivedConversationRequest = true;
            // Calculate secret key (to see they match)
            conversation = new Conversation(
                ndk,
                user,
                ndk.signer as NDKPrivateKeySigner,
                otherUser
            );
            decryptedConversationRequestMessage = await conversation.handleConversationRequest(
                conversationRequest,
                prekeySigner
            );
            receiverSecretKey = conversation.hexSecretKey();
        } else if (unwrapped.kind === 444) {
            console.log("📬 Received a new message");
            if (conversation) {
                conversation.handleIncomingMessage(unwrapped);
            } else {
                console.log("🚫 Received a message but no conversation exists");
            }
        } else {
            console.log("🚫 Received a gift-wrap event that is not a conversation request");
            return;
        }
    });

    onMount(async () => {
        await giftWrapSub.start();
    });

    function toggleConversationEventBlock() {
        showConversationEventBlock = !showConversationEventBlock;
    }

    function togglePrekeyEventBlock() {
        showPrekeyEventBlock = !showPrekeyEventBlock;
    }

    function showMessageForm() {
        conversationAccepted = true;
    }
</script>

<div class="max-w-[50%] border border-gray-400 rounded-md p-6 flex flex-col gap-4">
    <div class="flex flex-row gap-2 items-center">
        <Avatar {ndk} {user} class="rounded-full bg-transparent ring-1 ring-black w-12 h-12 my-0" />
        <div class="flex flex-col gap-0 truncate">
            <Name {ndk} pubkey={user.pubkey} class="font-medium text-lg" />
            <div class="text-xs truncate font-mono font-light">
                {user.pubkey}
            </div>
        </div>
    </div>
    <div class="text-sm">
        <h3>
            <Name {ndk} pubkey={user.pubkey} />'s Prekey
            <span class="text-base font-normal ml-4">
                <a on:click={togglePrekeyEventBlock} href="#">
                    {showPrekeyEventBlock ? "Hide" : "Show"} event
                </a>
            </span>
        </h3>

        {#if showPrekeyEventBlock}
            <pre>{JSON.stringify(prekey.rawEvent(), undefined, 2)}</pre>
        {/if}
    </div>
    <hr class="mt-0" />
    <div>
        <button
            disabled={conversationRequestSent}
            on:click={() => {
                conversationRequestSent = true;
                sentConversationRequest = true;
                dispatch("sendConversationRequest", {
                    ndk: ndk,
                    sender: user,
                    recipient: otherUser
                });
            }}
        >
            Send a conversation request to <Name {ndk} pubkey={otherUser.pubkey} />
        </button>
    </div>
    <div class="flex flex-col gap-2">
        {#if sentConversationRequest}
            <span class="block">✅ Conversation request sent</span>
        {:else if conversationRequestSent && !sentConversationRequest && receivedConversationRequest}
            <span class="block"
                >✅ Received conversation request <a
                    on:click={toggleConversationEventBlock}
                    href="#"
                >
                    {showConversationEventBlock ? "Hide" : "Show"} decrypted event
                </a></span
            >
            <span class="block">
                {#if showConversationEventBlock}
                    <pre class="mt-0 pt-0">{JSON.stringify(
                            conversationRequest?.rawEvent(),
                            undefined,
                            2
                        )}</pre>
                {/if}
            </span>
        {:else}
            <span class="block">⏳ Waiting for conversation requests</span>
        {/if}
        {#if initialSecretKey && sentConversationRequest}
            <span class="block">
                🔑 Sender calculated secret key: <span class="font-mono text-sm">
                    {initialSecretKey}
                </span>
            </span>
        {/if}
        {#if receiverSecretKey}
            <span class="block">
                🔑 Receiver calculated secret key <span
                    class="font-semibold {initialSecretKey === receiverSecretKey
                        ? 'text-green-600'
                        : 'text-red-600'}"
                    >{initialSecretKey === receiverSecretKey ? "MATCHES" : "DOESN'T MATCH"}</span
                >:
                <span
                    class="font-mono p-1 text-sm {initialSecretKey === receiverSecretKey
                        ? 'bg-green-300'
                        : 'bg-red-300'}"
                >
                    {receiverSecretKey}
                </span>
                <span class="text-sm italic"
                    >NB: We're only able to see this because we're doing everything in one page. In
                    real world use, you would only know that the request was valid if you could
                    decrypt the message.</span
                >
            </span>
            {#if decryptedConversationRequestMessage}
                <h4>
                    Conversation Request from <Name {ndk} pubkey={conversationRequest.pubkey} />
                </h4>
                <span class="flex flex-row gap-2 items-center">
                    <Avatar
                        {ndk}
                        pubkey={conversationRequest.pubkey}
                        class="rounded-full w-8 h-8 my-0"
                    />
                    {decryptedConversationRequestMessage}
                </span>

                {#if conversationAccepted}
                    <form>
                        <div class="flex flex-col gap-2">
                            <textarea
                                placeholder="What do you want to say?"
                                id="message"
                                class="border rounded-md p-2"
                            ></textarea>
                            <input type="submit" value="Send" class="border rounded-md p-2" />
                        </div>
                    </form>
                {:else}
                    <button on:click={showMessageForm} class="mt-4">Accept?</button>
                {/if}
            {/if}
        {/if}
    </div>
</div>
