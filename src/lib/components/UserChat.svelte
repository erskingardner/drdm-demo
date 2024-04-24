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
    export let initialRootKey: string | null;

    let sentConversationRequest = false;
    let receivedConversationRequest = false;
    let conversationRequest: NDKEvent | null = null;

    let showConversationEventBlock = false;
    let conversation: Conversation | null = null;
    let receiverRootKey: string;

    let giftWrapSub = ndk.subscribe({ kinds: [1059 as number], "#p": [user.pubkey] });
    giftWrapSub.on("event", async (event) => {
        conversationRequest = unwrap(ndk, event, ndk.signer! as NDKPrivateKeySigner);
        if (conversationRequest.kind === 443) {
            console.log("📨 Received a conversation request");
            receivedConversationRequest = true;
            // Calculate root key (to see they match)
            conversation = new Conversation(
                ndk,
                user,
                ndk.signer as NDKPrivateKeySigner,
                otherUser
            );
            await conversation.handleConversationRequest(conversationRequest, prekeySigner);
            receiverRootKey = conversation.hexRootKey();
        } else {
            console.log("🚫 Received a gift-wrap event that is not a conversation request");
            return;
        }
    });

    onMount(async () => {
        await giftWrapSub.start().then(() => {
            console.log("Subscribed to gift-wrapped events");
        });
    });

    function toggleConversationEventBlock() {
        showConversationEventBlock = !showConversationEventBlock;
    }
</script>

<div class="max-w-[50%] border border-gray-400 rounded-md p-6 flex flex-col gap-6">
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
        <h3><Name {ndk} pubkey={user.pubkey} />'s Prekey</h3>
        <pre>{JSON.stringify(prekey.rawEvent(), undefined, 2)}</pre>
    </div>
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
    <div>
        {#if sentConversationRequest}
            <span class="block">✅ Conversation request sent</span>
        {:else if conversationRequestSent && !sentConversationRequest && receivedConversationRequest}
            <span class="block"
                >✅ Received for conversation request <a
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
        {#if initialRootKey && sentConversationRequest}
            <span class="block">
                🔑 Sender calculated root key: <span class="font-mono text-sm">
                    {initialRootKey}
                </span>
            </span>
        {/if}
        {#if receiverRootKey}
            <span class="block">
                🔑 Receiver calculated root key <span
                    class="font-semibold {initialRootKey === receiverRootKey
                        ? 'text-green-600'
                        : 'text-red-600'}"
                    >{initialRootKey === receiverRootKey ? "MATCHES" : "DOESN'T MATCH"}</span
                >:
                <span
                    class="font-mono p-1 text-sm {initialRootKey === receiverRootKey
                        ? 'bg-green-300'
                        : 'bg-red-300'}"
                >
                    {receiverRootKey}
                </span>
            </span>
        {/if}
    </div>
</div>
