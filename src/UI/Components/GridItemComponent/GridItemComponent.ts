import {BaseComponent, CommonEvents, ComponentEvent, MouseEventButton} from "../../Base/BaseComponent/BaseComponent.js";
import {GridItemComponent as className} from "./GridItemComponent.module.css"
import {ParagraphComponent} from "../ParagraphComponent/ParagraphComponent.js";
import {GridLayout} from "../../Layouts/GridLayout/GridLayout.js";

export class GridItemComponent extends BaseComponent<GridLayout> {
    public events: CommonEvents[] = ["mousedown"];

    public constructor(private item?: BaseComponent) {
        super("GRID_ITEM", className);

        if (item)
            this.addChild(item);
    }

    protected async render(): Promise<string> {
        if (this.item)
            return this.item.renderRecursive();

        return "";
    }

    public handleEvent(event: ComponentEvent<"mousedown">) {
        if (event.data.button === MouseEventButton.LEFT) {
            (this.item as ParagraphComponent).setContent(`${Math.random()}`);
        }
    }
}