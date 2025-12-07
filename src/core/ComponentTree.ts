import {BaseComponent, ComponentEvent} from "../UI/Base/BaseComponent/BaseComponent.js";
import {AppComponent} from "../UI/Components/AppComponent/AppComponent.js";

export class ComponentTree {
    public static repaintQueue: BaseComponent<any>[] = [];

    public constructor(private app: AppComponent) {
        app.onMounted?.();
    }

    public findById(id: string, current: BaseComponent = this.app): BaseComponent | null {
        return current.findChildById(id);
    }

    public dispatchEvent(event: ComponentEvent) {
        const target = this.findById(event.target);
        if (!target) {
            console.warn(`Target '${event.target}' could not be found!`);
            return;
        }

        if (!target?.handleEvent) {
            console.warn(`Target '${event.target}' cannot handle events!`);
            return;
        }

        target.handleEvent(event);
    }

    public async renderFull(): Promise<string> {
        return this.app.renderRecursive();
    }

    public async renderById(id: string): Promise<string | null> {
        const target = this.findById(id);
        if (!target)
            throw new Error(`Target '${id}' could not be found!`);

        if (!target?.renderRecursive()) {
            console.warn(`Target '${target}' can not be rendered.`);
            return null;
        }

        return target.renderRecursive();
    }

    public findParentOf(id: string, current: BaseComponent = this.app): BaseComponent<any> | null {
        for (const child of current.children) {
            if (child.id === id)
                return current;

            const found = this.findParentOf(id, child);
            if (found)
                return found;
        }

        return null;
    }

    public replaceComponent(id: string, replacee: BaseComponent<any>): void {
        const parent = this.findParentOf(id);
        if (!parent)
            throw new Error(`Parent component of component '${id}' could not be found!`);

        parent.removeChildById(id);
        parent.addChild(replacee);

        replacee.parent = parent;
        replacee.onMounted?.();
    }

    public async getUpdatedComponents(): Promise<{ target: string, html: string }[]> {
        const components: { target: string, html: string }[] = [];
        while (ComponentTree.repaintQueue.length > 0) {
            const toUpdate = ComponentTree.repaintQueue.pop()!;
            components.push({target: toUpdate.id, html: await toUpdate.renderRecursive()});
        }

        return components;
    }

    public getApp(): AppComponent {
        return this.app;
    }
}