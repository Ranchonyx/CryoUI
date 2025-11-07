import {BaseComponent} from "../BaseComponent/BaseComponent.js";
import {BaseLayout as className} from "./BaseLayout.module.css"

export abstract class BaseLayout extends BaseComponent {
    protected constructor(id: string, className: string) {
        super(`LAYOUT_${id}`, `${className}`);
    }
}