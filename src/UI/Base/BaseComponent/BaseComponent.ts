export type CommonEvents = "click" | "input" | "change" | "contextmenu" | "submit" | "keydown";
export type ComponentEvent<K = CommonEvents | string, T = any> = { type: K, target: string, data: T };
import {BaseComponent as className} from "./BaseComponent.module.css"

export abstract class BaseComponent {
    public id: string;
    public parent?: BaseComponent;
    public children: BaseComponent[] = []
    public events?: CommonEvents[] = [];

    protected constructor(id: string, public className: string, public styleOverrides?: Record<string, string>) {
        this.id = `${id}-${crypto.randomUUID()}`
    }

    public handleEvent?(event: ComponentEvent): void;

    public onMounted?(): void;

    public onDestroyed?(): void;

    protected abstract render(): Promise<string>;

    public async renderRecursive(): Promise<string> {
/*
        console.info(`Rendering ${this.className} ...`);
*/
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

}