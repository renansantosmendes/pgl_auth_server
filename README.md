# pgl_auth_server

API serverless (FastAPI) hospedada no Vercel que autentica alunos (matrícula + senha) e
emite um token JWT de curta duração (4 horas) para acesso ao proxy dos modelos de IA da
disciplina.

Este é o servidor. O pacote Python instalado pelos alunos (`pgl-auth`, publicado no PyPI)
que consome esta API fica em um repositório separado (`pgl_auth`).

## Estrutura

- `api/application.py` — entrypoint serverless usado pela Vercel (`[tool.vercel] entrypoint`
  em `pyproject.toml` aponta para cá). Só monta a `FastAPI app` a partir de `core/app.py`;
  não tem lógica de negócio.
- `core/` — lógica da aplicação, organizada por responsabilidade:
  - `core/app.py` — factory `create_app()` que instancia a `FastAPI`, registra as rotas e,
    se `ALLOWED_FRONTEND_ORIGINS` estiver configurada, habilita CORS (só `POST`) para essas
    origens — necessário para que uma página como `pgl-registry-front` chame `/api/register`
    diretamente do navegador via `fetch()`. Sem essa variável, a API não é alcançável por
    nenhuma página web (o `pgl_auth` e o `pgl_proxy` chamam esta API do lado do servidor,
    onde CORS não se aplica).
  - `core/routers/auth.py` — endpoints de autenticação:
    - `POST /api/login` — valida matrícula/senha (hash bcrypt) contra `pgl_auth.students`
      no Postgres (Neon) e assina o JWT.
    - `POST /api/register` — cadastra um novo aluno (matrícula + senha) em
      `pgl_auth.students`, com a senha já hasheada em bcrypt. Só permite o cadastro se a
      matrícula existir e estiver ativa em `pgl_proxy.students` (`403` caso contrário).
      Retorna `409` se a matrícula já existir em `pgl_auth.students`.
  - `core/db.py` — conexão com o Postgres (`get_connection()`).
  - `core/security.py` — hashing/verificação de senha (bcrypt) e o fingerprint SHA-256
    usado só para correlacionar tentativas nos logs, sem nunca expor a senha.
  - `core/config.py` — configuração de logging e constantes (`TOKEN_TTL`).
- `requirements.txt` — dependências da função (fastapi, psycopg2-binary, bcrypt, PyJWT, pydantic).
- `pyproject.toml` — **não é o pacote PyPI**. Declara `[tool.vercel] entrypoint` (para a
  Vercel achar `api/application.py`) e `[project]`/`dependencies`, que é a fonte de verdade
  das dependências no deploy: o build da Vercel usa `uv` e falha com `No project table found`
  se o `pyproject.toml` existir sem uma tabela `[project]`. `requirements.txt` e
  `requirements-dev.txt` existem só para desenvolvimento local/CI e ficam de fora do bundle
  (`.vercelignore`) para não conflitar com o `pyproject.toml` durante o `uv lock`.
- `uv.lock` — lockfile commitado para builds determinísticos na Vercel. Regenere com
  `uv lock` sempre que alterar `dependencies` em `pyproject.toml`.

## Rodando localmente

```bash
pip install -r requirements.txt fastapi[standard]  # uvicorn vem com o extra "standard"
cp .env.example .env   # preencha NEON_DATABASE_URL e JWT_SECRET_KEY
fastapi dev api/application.py
```

## Deploy no Vercel

1. Importe este repositório no Vercel (Project → Add New → Project).
2. **Não precisa mexer em Root Directory** — este repositório já é só a API, sem nenhum
   outro `pyproject.toml`/pacote competindo por atenção.
3. Configure as variáveis de ambiente do projeto:
   - `NEON_DATABASE_URL`
   - `JWT_SECRET_KEY`
   - `ALLOWED_FRONTEND_ORIGINS` — opcional, origens (separadas por vírgula) autorizadas a
     chamar `/api/register` via CORS a partir do navegador, ex.
     `https://pgl-registry-front.vercel.app`. Deixe sem definir para manter a API
     inacessível a partir de qualquer página web.
4. Deploy automático a cada push — os endpoints ficam em
   `https://<projeto>.vercel.app/api/login` e `https://<projeto>.vercel.app/api/register`.
5. Depois do primeiro deploy, atualize `DEFAULT_API_URL` em `pgl_auth/src/pgl_auth/client.py`
   (no outro repositório) com essa URL, ou oriente os alunos a definir a variável de
   ambiente `PGL_AUTH_API_URL`.

Não é preciso `vercel.json`: declarar `runtime` manualmente lá costuma quebrar com
"Function Runtimes must have a valid version" se a versão não for pinada.

## Banco de dados

O schema `pgl_auth` (tabela `students`) e o schema `pgl_proxy` (tabela `students`, que
guarda quem está matriculado/ativo) são provisionados a partir do repositório `pgl_auth`
(`db/migrate.py`). O cadastro de alunos (`db/create_student.py` naquele repositório, ou
`POST /api/register` aqui) escreve em `pgl_auth.students`.
