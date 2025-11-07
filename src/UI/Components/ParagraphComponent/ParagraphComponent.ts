import {BaseComponent} from "../../Base/BaseComponent/BaseComponent.js";
import {ParagraphComponent as className} from "./ParagraphComponent.module.css"

export class ParagraphComponent extends BaseComponent {
    public constructor(private content?: string) {
        super("PARAGRAPH", className);
    }

    public async render(): Promise<string> {
        return `<p>${this.content || ""}</p>`;
    }

    public setContent(content: string): void {
        this.content = content;
    }
}