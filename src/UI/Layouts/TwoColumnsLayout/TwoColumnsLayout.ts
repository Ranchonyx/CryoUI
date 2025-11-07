import {BaseComponent, ComponentEvent} from "../../Base/BaseComponent/BaseComponent.js";
import {BaseLayout} from "../../Base/BaseLayout/BaseLayout.js";
import {TwoColumnsLayout as className} from "./TwoColumnsLayout.module.css"

export class TwoColumnsLayout extends BaseLayout {
    public constructor(private left?: BaseComponent, private right?: BaseComponent) {
        super("TWO_COLUMNS", className);

        if(left)
            this.addChild(left);

        if(right)
            this.addChild(right);
    }

    public setLeft(value: BaseComponent): void {
        this.left = value;
        this.addChild(this.left);
    }

    public setRight(value: BaseComponent): void {
        this.right = value;
        this.addChild(this.right);
    }

    public async render(): Promise<string> {
        return [await this.left?.renderRecursive(), await this.right?.renderRecursive()].join("");
    }

    public handleEvent(event: ComponentEvent) {
        this.left?.handleEvent?.(event);
        this.right?.handleEvent?.(event);
    }
}