# pgl_auth_server

API serverless (FastAPI) hospedada no Vercel que autentica alunos (matrícula + senha) e
emite um token JWT de curta duração (4 horas) para acesso ao proxy dos modelos de IA da
disciplina.

Este é o servidor. O pacote Python instalado pelos alunos (`pgl-auth`, publicado no PyPI)
que consome esta API fica em um repositório separado (`pgl_auth`).

## Estrutura

- `api/login.py` — função serverless com o endpoint `POST /api/login`. Valida matrícula/senha
  (hash bcrypt) contra `pgl_auth.students` no Postgres (Neon) e assina o JWT.
- `requirements.txt` — dependências da função (fastapi, psycopg2-binary, bcrypt, PyJWT, pydantic).
- `pyproject.toml` — **não é o pacote PyPI**. Declara `[tool.vercel] entrypoint` (para a
  Vercel achar `api/login.py`) e `[project]`/`dependencies`, que é a fonte de verdade das
  dependências no deploy: o build da Vercel usa `uv` e falha com `No project table found`
  se o `pyproject.toml` existir sem uma tabela `[project]`. `requirements.txt` e
  `requirements-dev.txt` existem só para desenvolvimento local/CI e ficam de fora do bundle
  (`.vercelignore`) para não conflitar com o `pyproject.toml` durante o `uv lock`.
- `uv.lock` — lockfile commitado para builds determinísticos na Vercel. Regenere com
  `uv lock` sempre que alterar `dependencies` em `pyproject.toml`.

## Rodando localmente

```bash
pip install -r requirements.txt fastapi[standard]  # uvicorn vem com o extra "standard"
cp .env.example .env   # preencha NEON_DATABASE_URL e JWT_SECRET_KEY
fastapi dev api/login.py
```

## Deploy no Vercel

1. Importe este repositório no Vercel (Project → Add New → Project).
2. **Não precisa mexer em Root Directory** — este repositório já é só a API, sem nenhum
   outro `pyproject.toml`/pacote competindo por atenção.
3. Configure as variáveis de ambiente do projeto:
   - `NEON_DATABASE_URL`
   - `JWT_SECRET_KEY`
4. Deploy automático a cada push — o endpoint fica em `https://<projeto>.vercel.app/api/login`.
5. Depois do primeiro deploy, atualize `DEFAULT_API_URL` em `pgl_auth/src/pgl_auth/client.py`
   (no outro repositório) com essa URL, ou oriente os alunos a definir a variável de
   ambiente `PGL_AUTH_API_URL`.

Não é preciso `vercel.json`: declarar `runtime` manualmente lá costuma quebrar com
"Function Runtimes must have a valid version" se a versão não for pinada.

## Banco de dados

O schema `pgl_auth` (tabela `students`) e o schema `pgl_proxy` (tabela `students`, que
guarda quem está matriculado/ativo) são provisionados e administrados a partir do
repositório `pgl_auth` (`db/migrate.py`, `db/create_student.py`). Esta API só lê/autentica
contra `pgl_auth.students` — não faz nenhuma escrita administrativa.
