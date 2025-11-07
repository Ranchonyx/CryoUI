import {BaseComponent, CommonEvents, ComponentEvent} from "../../Base/BaseComponent/BaseComponent.js";
import {GridItemComponent as className} from "./GridItemComponent.module.css"
import {ParagraphComponent} from "../ParagraphComponent/ParagraphComponent.js";

export class GridItemComponent extends BaseComponent {
    public events: CommonEvents[] = ["click"];

    public constructor(private item?: BaseComponent) {
        super("GRID_ITEM", className);

        if (item)
            this.addChild(item);
    }

    public async render(): Promise<string> {
        if (this.item)
            return this.item.renderRecursive();

        return "";
    }

    public handleEvent(event: ComponentEvent) {
        switch (event.type) {
            case "click":
                (this.item as ParagraphComponent).setContent(`${Math.random()}`);
                break;
            default:
                return;
        }
    }
}