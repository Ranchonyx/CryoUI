import {BaseComponent, ComponentEvent} from "../../Base/BaseComponent/BaseComponent.js";
import {GridLayout as className} from "./GridLayout.module.css"
import {GridItemComponent} from "../../Components/GridItemComponent/GridItemComponent.js";

export class GridLayout extends BaseComponent {
    public constructor(items: GridItemComponent[] = []) {
        super("GRID", className);

        for(const item of items)
            this.addChild(item);
    }

    protected async render(): Promise<string> {
        const renderedChildren = await Promise.all(this.children.map(child => child.renderRecursive()));
        return renderedChildren.join("");
    }

    public handleEvent(event: ComponentEvent) {
        for (const child of this.children) {
            child.handleEvent?.(event);
        }
    }
}