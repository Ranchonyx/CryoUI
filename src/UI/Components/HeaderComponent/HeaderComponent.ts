import {BaseComponent} from "../../Base/BaseComponent/BaseComponent.js";
import {HeaderComponent as className} from "./HeaderComponent.module.css"

export class HeaderComponent extends BaseComponent {
    public constructor(private content: string = "", private size: 1 | 2 | 3 | 4 | 5 | 6 = 1) {
        super("HEADER", className);
    }

    public async render(): Promise<string> {
        return `<h${this.size}>${this.content}</h${this.size}>`;
    }

    public setContent(content: string): void {
        this.content = content;
    }
}