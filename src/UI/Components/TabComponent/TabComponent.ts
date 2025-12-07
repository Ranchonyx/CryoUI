import {BaseComponent, CommonEvents, ComponentEvent, MouseEventButton} from "../../Base/BaseComponent/BaseComponent.js";
import {TabComponent as className} from "./TabComponent.module.css"
import {BaseLayout} from "../../Base/BaseLayout/BaseLayout.js";
import {NavbarComponent} from "../NavbarComponent/NavbarComponent.js";

export class TabComponent extends BaseComponent<NavbarComponent, "mousedown"> {
    public events: CommonEvents[] = ["mousedown"];
    public active: boolean = false;

    public constructor(private text: string, private heldLayout?: BaseLayout) {
        super("TAB", className);

        if (this.heldLayout)
            this.addChild(this.heldLayout);
    }

    protected async render(): Promise<string> {
        return `<div data-active="${this.active}">${this.text}</div>`;
    }

    public setLayout(layout: BaseLayout): void {
        this.heldLayout?.onDestroyed?.();
        this.children = [];

        this.heldLayout = layout;
        this.addChild(layout);

        this.heldLayout?.onMounted?.();
    }

    public tryGetLayout(): BaseLayout | null {
        if (!this.heldLayout)
            return null;

        return this.heldLayout;
    }

    public getLayoutOrThrow(): BaseLayout {
        if (!this.heldLayout)
            throw new Error("Unable to get layout. It has not been set.");
        return this.heldLayout;
    }

    handleEvent(event: ComponentEvent<"mousedown">): void {
        //On left click
        if (event.data.button === MouseEventButton.LEFT) {
            if (this.active)
                return;

            this.parent
                ?.getTabs()
                .forEach((tab: TabComponent) => tab.active = false);

            this.active = true;

            this.getApp().markDirty();
        }
    }
}