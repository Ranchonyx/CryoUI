import {randomUUID, UUID} from "node:crypto";

export type CommonEvents = "click" | "input" | "change" | "contextmenu" | "submit" | "keydown";
export type ComponentEvent<T = any> = { type: CommonEvents, target: string, data: T };
import {BaseComponent as className} from "./BaseComponent.module.css"
import {ComponentTree} from "../../../core/ComponentTree.js";

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

export abstract class BaseComponent {
    public id: string;
    public parent?: BaseComponent;
    public children: BaseComponent[] = []
    public events?: CommonEvents[] = [];
    private dirty: boolean = false;

    protected constructor(id: string, public className: string, public styleOverrides?: Record<string, string>) {
        this.id = `${id}-${UUIDPool.Instance.get()}`
    }

    public handleEvent?(event: ComponentEvent): void;

    public onMounted?(): void;

    public onDestroyed?(): void;

    protected abstract render(): Promise<string>;

    public async renderRecursive(): Promise<string> {
        if (this.dirty)
            this.dirty = false;
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

    public addChild(child: BaseComponent) {
        child.parent = this;
        this.children.push(child);
    }

    public removeChild(child_id: string) {
        this.children = this.children.filter((child) => child_id !== child.id);
    }

    public findById(id: string): BaseComponent | null {
        /*console.log(`Checking ${this.id} against target id ${id}`)
        */
        if (this.id === id)
            return this;

        for (const child of this.children) {
            const found = child.findById(id);
            if (found)
                return found;
        }

        return null;
    }

    public repaint(): void {
        ComponentTree.repaintQueue.push(this);
    }
}