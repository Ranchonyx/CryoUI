import {cryo, ITokenValidator} from "cryo-server"
import {ComponentEvent} from "./UI/Base/BaseComponent/BaseComponent.js";
import {ComponentTree} from "./core/ComponentTree.js";
import {AppComponent} from "./UI/Components/AppComponent/AppComponent.js";
import {TwoColumnsLayout} from "./UI/Layouts/TwoColumnsLayout/TwoColumnsLayout.js";
import {GridLayout} from "./UI/Layouts/GridLayout/GridLayout.js";
import {FrameComponent} from "./UI/Components/FrameComponent/FrameComponent.js";
import {GridItemComponent} from "./UI/Components/GridItemComponent/GridItemComponent.js";
import {ParagraphComponent} from "./UI/Components/ParagraphComponent/ParagraphComponent.js";
import {NavbarComponent} from "./UI/Components/NavbarComponent/NavbarComponent.js";
import {HeaderComponent} from "./UI/Components/HeaderComponent/HeaderComponent.js";
import {inspect} from "node:util";
import {TabComponent} from "./UI/Components/TabComponent/TabComponent.js";

const PORT = 8080;

class Validator implements ITokenValidator {
    public async validate(token: string): Promise<boolean> {
        return token === "test";
    }
}

const server = await cryo(new Validator(), {use_cale: false, port: PORT, keepAliveIntervalMs: 60000});

server.on("session", async (session) => {
    console.log(`New session '${session.id}' connected!`);
    //Main closure for application state on the frontend

    const initialTab = new TabComponent(
        "Home",
        new TwoColumnsLayout(
            new GridLayout(
                [
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 1 1")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 1 2")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 1 3")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 1 4")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 1 5")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 1 6")),
                ]
            ),
            new FrameComponent([
                new HeaderComponent("Fantastic Page 1 header right here!"),
                new ParagraphComponent(`Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.`),
            ])
        ));

    const secondTab = new TabComponent(
        "More",
        new TwoColumnsLayout(
            new GridLayout(
                [
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 2 1")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 2 2")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 2 3")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 2 4")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 2 5")),
                    new GridItemComponent(new ParagraphComponent("Grid Item Page 2 6")),
                ]
            ),
            new FrameComponent([
                new HeaderComponent("Fantastic Page 2 header right here!"),
                new ParagraphComponent(`Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.`),
            ])
        ));


    const app = new AppComponent(
        new NavbarComponent(
            [
                new ParagraphComponent("Btn 1"),
                new ParagraphComponent("Btn 2")
            ],
            [
                initialTab,
                secondTab
            ]
        ),
    );

    //Render UI initially and send to client
    const tree = new ComponentTree(app);
    await session.SendUTF8(JSON.stringify({target: "root", html: await tree.renderFull()}));

    session.on("message-utf8", async (message) => {
        const {type, data, target} = JSON.parse(message) as ComponentEvent;
        console.log(`Received UIEvent '${type}' on '${target}' with data '${inspect(data, false, 6, true)}'`);

        tree.dispatchEvent({target, data, type});

        const html = await tree.renderById(target);
        if (html) {
            console.info(`UIEvent '${type}' on '${target}' => '${target}' was re-rendered!`);
            await session.SendUTF8(JSON.stringify({target, html}));
        }

        const maybeRepainted = await tree.getUpdatedComponents();
        if (maybeRepainted.length === 0)
            return;

        console.info(`UIEvent '${type}' on '${target}' => '${maybeRepainted.length}' components were re-rendered!`);
        for (const {target, html} of maybeRepainted) {
            await session.SendUTF8(JSON.stringify({target, html}));
        }
    });

    session.on("closed", () => {
        console.log(`Session '${session.id}' closed`);
    })
});

server.on("listening", () => {
    console.log(`CryoUI listening on port ${PORT}`);
});