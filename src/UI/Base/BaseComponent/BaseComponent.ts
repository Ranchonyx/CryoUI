import {randomUUID, UUID} from "node:crypto";
import {BaseComponent as className} from "./BaseComponent.module.css"
import {ComponentTree} from "../../../core/ComponentTree.js";
import {AppComponent} from "../../Components/AppComponent/AppComponent.js";

export enum MouseEventButton {
    LEFT,
    MIDDLE,
    RIGHT,
    BACKWARDS,
    FORWARDS
}

export type EventDataMap = {
    submit: Record<string, any>,
    mousedown: Pick<MouseEvent, "ctrlKey" | "altKey"> & { button: MouseEventButton };
    keydown: Pick<KeyboardEvent, 'altKey' | 'ctrlKey' | 'shiftKey' | 'metaKey' | 'key' | 'code' | 'repeat'>;
}

export type CommonEvents = keyof EventDataMap;
export type ComponentEvent<TEvent extends CommonEvents = CommonEvents> = {
    type: TEvent,
    target: string,
    data: EventDataMap[TEvent]
};

class UUIDPool {
    private static _instance: UUIDPool | undefined = undefined;
    private uuids: Set<UUID> = new Set();

    public get(): UUID {
        const newUUID = randomUUID();
        if (this.uuids.has(newUUID))
            return this.get();

        this.uuids.add(newUUID);
        return newUUID;
    }

    public static get Instance(): UUIDPool {
        if (!UUIDPool._instance)
            UUIDPool._instance = new UUIDPool();

        return UUIDPool._instance;
    }
}

type AnyBaseComponent = BaseComponent<any>;

export abstract class BaseComponent<
    TParentComponentType extends AnyBaseComponent | null = null,
    TEventType extends CommonEvents = CommonEvents
> {
    /**
     * The unique ID of this component instance
     * */
    public readonly id: string;

    /**
     * A reference to this component instance's parent
     * */
    public parent?: TParentComponentType;

    /**
     * An array containing the children of this component instance
     * */
    public children: BaseComponent[] = []

    /**
     * Optionally, an array of browser-events which should be bound to this component
     * */
    public events?: CommonEvents[] = [];

    protected constructor(id: string, public className: string, public styleOverrides?: Record<string, string>) {
        this.id = `${id}-${UUIDPool.Instance.get()}`
    }

    /**
     * Optionally, this method will be called when the component receives a bound event.
     *
     * This method **must** be implemented when {@link events} is implemented!
     * @see{events}
     * */
    public abstract handleEvent(event: ComponentEvent<TEventType>): void;

    /**
     * Executed when this component is added to the DOM
     * */
    public onMounted?(): void;

    /**
     * Executed when this component is removed from the DOM
     * */
    public onDestroyed?(): void;


    /**
     * This method must be implemented.
     *
     * It shall return a valid HTML-Markup string describing the layout of this component.
     * */
    protected abstract render(): Promise<string>;

    /**
     * This method renders this component with all children recursively
     * */
    public async renderRecursive(): Promise<string> {
        const rendered = await this.render();

        let computedStyle = "";
        let dataEvent = "";

        if (this.styleOverrides)
            computedStyle = `style="${Object.entries(this.styleOverrides).reduce((sheet, entry) => sheet + `${entry[0]}: ${entry[1]};`, "")}"`;

        if (this.events && this.events.length > 0)
            dataEvent = `data-event="${this.events.join(",")}"`;

        return `
                <div data-target="${this.id}" ${dataEvent}${computedStyle} class="${className} ${this.className}">
                    ${rendered}
                </div>`
    }

    /**
     * Add a child component
     * */
    public addChild(child: BaseComponent<any>) {
        child.parent = this;
        this.children.push(child);
    }

    /**
     * Remove a child component by its ID
     * */
    public removeChildById(child_id: string): BaseComponent | null {
        const chIdx = this.children.findIndex(child => child.id === child_id);
        if (chIdx < 0)
            return null;

        return this.children.splice(chIdx, 1)[0];
    }

    /**
     * Recursively find a child component by its ID in all child components recursively
     * */
    public findChildById(id: string): BaseComponent<any> | null {
        if (this.id === id)
            return this;

        for (const child of this.children) {
            const found = child.findChildById(id);
            if (found)
                return found;
        }

        return null;
    }

    /**
     * Forces this component instance to be redrawn
     * */
    public markDirty(): void {
        ComponentTree.repaintQueue.push(this);
    }

    public getApp(): AppComponent {
        let cur: BaseComponent<any> | undefined = this;
        while (cur?.parent !== undefined) {
            cur = cur?.parent;
        }

        return cur as AppComponent;
    }
}