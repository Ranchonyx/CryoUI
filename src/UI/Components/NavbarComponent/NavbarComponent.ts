import {BaseComponent, ComponentEvent} from "../../Base/BaseComponent/BaseComponent.js";
import {NavbarComponent as className, buttons, tabs} from "./NavbarComponent.module.css"
import {TabComponent} from "../TabComponent/TabComponent.js";
import {AppComponent} from "../AppComponent/AppComponent.js";

export class NavbarComponent extends BaseComponent<AppComponent> {
    public constructor(private buttons: BaseComponent[] = [], private tabs: TabComponent[] = []) {
        super("NAVBAR", className);

        if (tabs.length > 0)
            tabs[0].active = true;

        for (const child of [...this.buttons, ...this.tabs])
            this.addChild(child);
    }

    protected async render(): Promise<string> {
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
        this.removeChildById(target_id);
    }

    public addTab(tab: TabComponent): void {
        this.tabs.push(tab);
        this.addChild(tab);
    }

    public removeTab(target_id: string): void {
        this.tabs = this.tabs.filter(tab => tab.id !== target_id);
        this.removeChildById(target_id);
    }

    public getTabs(): TabComponent[] {
        return this.tabs;
    }

    public getActiveTab(): TabComponent {
        return this.tabs.find(tab => tab.active)!;
    }

    public handleEvent(event: ComponentEvent) {
        for (const child of this.children) {
            child.handleEvent?.(event);
        }
    }
}