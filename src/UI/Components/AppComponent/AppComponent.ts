import {BaseComponent} from "../../Base/BaseComponent/BaseComponent.js";
import {AppComponent as className} from "./AppComponent.module.css"
import {BaseLayout} from "../../Base/BaseLayout/BaseLayout.js";

export class AppComponent extends BaseComponent {
    public constructor(private navBar: BaseComponent, private mainContent: BaseLayout) {
        super("APP", className);

        this.addChild(navBar);
        this.addChild(mainContent);
    }

    public async render(): Promise<string> {
        const renderedNavigation = await this.navBar.renderRecursive();
        const renderedContent = await this.mainContent.renderRecursive();
        return `${renderedNavigation}${renderedContent}`;
    }
}