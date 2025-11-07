import {BaseComponent} from "../../Base/BaseComponent/BaseComponent.js";
import {InputComponent as className} from "./InputComponent.module.css"

type InputTypes = "checkbox" | "radio" | "color" | "date" | "email" | "time" | "text" | "number";

export class InputComponent extends BaseComponent {
    public constructor(private label: string, private key: string, private type: InputTypes = "text") {
        super("INPUT", className);
    }

    public async render(): Promise<string> {
        const input = `<input required id="__${this.id}" step="0.01" name="${this.key}" type="${this.type}" />`;
        const label = `<label for="__${this.id}">${this.label}</label>`
        return `${label}${input}`;
    }
}