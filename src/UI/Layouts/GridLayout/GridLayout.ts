import {BaseComponent, ComponentEvent} from "../../Base/BaseComponent/BaseComponent.js";
import {GridLayout as className} from "./GridLayout.module.css"

export class GridLayout extends BaseComponent {
    public constructor(items: BaseComponent[] = []) {
        super("GRID", className);

        for(const item of items)
            this.addChild(item);
    }

    public async render(): Promise<string> {
        const renderedChildren = await Promise.all(this.children.map(child => child.renderRecursive()));
        return renderedChildren.join("");
    }

    public handleEvent(event: ComponentEvent) {
        for (const child of this.children) {
            child.handleEvent?.(event);
        }
    }
}