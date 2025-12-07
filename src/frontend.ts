import {cryo} from "cryo-client-browser"
import {ComponentEvent} from "./UI/Base/BaseComponent/BaseComponent.js";

type IncomingMessage = {
    html: string;
    target: string;
    events: ComponentEvent;
}

function cast<T>(_: unknown): asserts _ is T {
}

document.addEventListener("DOMContentLoaded", async () => {
    const client = await cryo("ws://localhost:8080", "test", false);

    client.on("connected", () => {
        console.info("Connected to backend.");
    });

    client.on("reconnected", async () => {
        console.info("Reconnected to backend.");
    });

    client.on("disconnected", async () => {
        console.info("Disconnected from backend.");
    });

    client.on("closed", async () => {
        console.info("Backend connection closed.");
    });

    client.on("message-utf8", (message) => {
        const {html, target, /*events*/} = JSON.parse(message) as IncomingMessage;
        console.info(`Got UI data from the backend. Rendering '${target}'`)
        const domElement = document.querySelector(`[data-target=${target}]`);
        if (!domElement) {
            throw new Error(`Element with data-target '${target}' not found in DOM!`);
        }

        domElement.outerHTML = html;

        document.querySelectorAll("[data-event]")
            .forEach((element) => {
                const eventTypes = element.getAttribute("data-event");
                const eventTarget = element.getAttribute("data-target");

                if (!eventTypes) {
                    console.warn(`Element with data-target '${element.id}' either has no data-event property or it has no value.`);
                    return;
                }

                if (!eventTarget) {
                    console.warn(`Element with data-target '${element.id}' either has no data-target property or it has no value.`);
                    return;
                }

                eventTypes
                    .split(",")
                    .forEach((eventType) => {
                        element
                            .addEventListener(eventType, (e) => {
                                let data: Record<string, any>;

                                switch (eventType) {
                                    case "mousedown":
                                        cast<MouseEvent>(e);
                                        data = {
                                            button: e.button,
                                            ctrlKey: e.ctrlKey,
                                            altKey: e.altKey
                                        };
                                        break;
                                    case "submit":
                                        data = Object.fromEntries((new FormData(e.target as HTMLFormElement) as unknown as Iterable<readonly [PropertyKey, string | undefined]>));
                                        break;
                                    case "keydown":
                                        cast<KeyboardEvent>(e);
                                        data = {
                                            key: e.key,
                                            altKey: e.altKey,
                                            shiftKey: e.shiftKey,
                                            ctrlKey: e.ctrlKey,
                                            metaKey: e.metaKey,
                                            code: e.code,
                                            repeat: e.repeat
                                        }
                                        break;
                                    default:
                                        data = Object.fromEntries(Object.entries(((element as HTMLElement)?.dataset || {})));
                                        delete data?.event;
                                        delete data?.target;
                                        break;
                                }

                                client.SendUTF8(JSON.stringify({type: eventType, target: eventTarget, data}));
                            })
                    })
            });
    });
})