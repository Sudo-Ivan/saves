# saves

Content-addressed, deduplicated save-game sync server and client.

## Install

    go install github.com/Sudo-Ivan/saves/cmd/savesd@latest
    go install github.com/Sudo-Ivan/saves/cmd/savesctl@latest

## Usage

    savesd -config saves.json
    savesctl push ./world --app minecraft-java --slot "My World"

See docs/config.md for configuration reference.

## License

0BSD.
