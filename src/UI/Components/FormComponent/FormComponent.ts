import {BaseComponent, CommonEvents, ComponentEvent} from "../../Base/BaseComponent/BaseComponent.js";
import {FormComponent as className} from "./FormComponent.module.css"
import {InputComponent} from "../InputComponent/InputComponent.js";

export class FormComponent extends BaseComponent {
    public events: CommonEvents[] = ["submit"];

    public constructor(private inputs: InputComponent[]) {
        super("FORM", className);

        for (const input of inputs)
            this.addChild(input);
    }

    protected async render(): Promise<string> {
        const rendered = await Promise.all(this.children.map(child => child.renderRecursive()));
        const renderedSubmissiveButton = `<input type="submit" value="Submit"/>`
        return `<form>${rendered.join("")}${renderedSubmissiveButton}></form>`;
    }

    public handleEvent(event: ComponentEvent) {
        switch (event.type) {
            case "submit":
                /*
                */
                break;
            default:
                return;
        }
    }
}