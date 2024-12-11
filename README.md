## 작동 방법
1. server.js를 다른 곳에다 database.db와 함께 복사 또는 이동 후 `node server.js`로 백 서버 실행
2. 이후 다시 이곳에서 `npm run dev`로 프론트 서버 실행
3. chrome 같은 인터넷 브라우저에서 `localhost:4321`로 접속
4. 임시 계정 이름은 `test` 비번은 `1357`

## 🧞 Commands

All commands are run from the root of the project, from a terminal:

| Command                   | Action                                           |
| :------------------------ | :----------------------------------------------- |
| `npm install`             | Installs dependencies                            |
| `npm run dev`             | Starts local dev server at `localhost:4321` 이 명령어를 주로 사용      |
| `npm run build`           | Build your production site to `./dist/`          |
| `npm run preview`         | Preview your build locally, before deploying     |
| `npm run astro ...`       | Run CLI commands like `astro add`, `astro check` |
| `npm run astro -- --help` | Get help using the Astro CLI                     |
