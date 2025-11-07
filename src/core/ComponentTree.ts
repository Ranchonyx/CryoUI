import {BaseComponent, ComponentEvent} from "../UI/Base/BaseComponent/BaseComponent.js";

export class ComponentTree {
    public constructor(public root: BaseComponent) {
        root.onMounted?.();
    }

    public findById(id: string, current: BaseComponent = this.root): BaseComponent | null {
        return current.findById(id);
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
        return this.root.renderRecursive();
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

    public findParentOf(id: string, current: BaseComponent = this.root): BaseComponent | null {
        for (const child of current.children) {
            if (child.id === id)
                return current;

            const found = this.findParentOf(id, child);
            if (found)
                return found;
        }

        return null;
    }

    public replaceComponent(id: string, replacee: BaseComponent): void {
        const parent = this.findParentOf(id);
        if(!parent)
            throw new Error(`Parent component of component '${id}' could not be found!`);

        parent.removeChild(id);
        parent.addChild(replacee);

        replacee.parent = parent;
        replacee.onMounted?.();
    }
}