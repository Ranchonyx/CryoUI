import {BaseComponent, ComponentEvent} from "../../Base/BaseComponent/BaseComponent.js";

export class FrameComponent extends BaseComponent {
    public constructor(children: BaseComponent[] = []) {
        super("FRAME", "frameComponent");

        for(const child of children)
            this.addChild(child);
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