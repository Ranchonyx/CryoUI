import {BaseComponent} from "../../Base/BaseComponent/BaseComponent.js";
import {AppComponent as className} from "./AppComponent.module.css"
import {BaseLayout} from "../../Base/BaseLayout/BaseLayout.js";
import {NavbarComponent} from "../NavbarComponent/NavbarComponent.js";

export class AppComponent extends BaseComponent {
    public constructor(private readonly navbar: NavbarComponent) {
        super("APP", className);

        this.addChild(navbar);
    }

    protected async render(): Promise<string> {
        const renderedNavigation = await this.navbar.renderRecursive();

        //Render the held layout of the active tab
        const renderedContent = await this.navbar
            .getActiveTab()
            .getLayoutOrThrow()
            .renderRecursive();

        return `${renderedNavigation}${renderedContent}`;
    }

    public getNavbar(): NavbarComponent {
        return this.navbar;
    }
}