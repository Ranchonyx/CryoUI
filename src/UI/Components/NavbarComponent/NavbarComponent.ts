import {BaseComponent, ComponentEvent} from "../../Base/BaseComponent/BaseComponent.js";
import {NavbarComponent as className, tabs, buttons} from "./NavbarComponent.module.css"

export class NavbarComponent extends BaseComponent {
    public constructor(private buttons: BaseComponent[] = [], private tabs: BaseComponent[] = []) {
        super("NAVBAR", className);

        for (const child of [...this.buttons, ...this.tabs])
            this.addChild(child);
    }

    public async render(): Promise<string> {
        const renderedButtons = await Promise.all(this.buttons.map(button => button.renderRecursive()));
        const renderedTabs = await Promise.all(this.tabs.map(tab => tab.renderRecursive()));

        return `
            <div class="${tabs}">${renderedTabs.join("")}</div>
            <div class="${buttons}">${renderedButtons.join("")}</div>
        `;
    }

    public addButton(button: BaseComponent): void {
        this.buttons.push(button);
        this.addChild(button);
    }

    public removeButton(target_id: string): void {
        this.buttons = this.buttons.filter(button => button.id !== target_id);
        this.removeChild(target_id);
    }

    public addTab(tab: BaseComponent): void {
        this.tabs.push(tab);
        this.addChild(tab);
    }

    public removeTab(target_id: string): void {
        this.tabs = this.tabs.filter(tab => tab.id !== target_id);
        this.removeChild(target_id);
    }

    public handleEvent(event: ComponentEvent) {
        for (const child of this.children) {
            child.handleEvent?.(event);
        }
    }
}