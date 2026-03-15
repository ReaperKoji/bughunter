# Bounty Platform (Django + ORM + Redis)

Stack modular para pesquisas autorizadas, com persistencia de ativos/subdominios/vulnerabilidades.

## Subir ambiente

```bash
cp .env.example .env
docker compose up -d --build
```

## Migracoes

```bash
docker compose exec web python manage.py makemigrations
docker compose exec web python manage.py migrate
```

## Criar programa e escopo

```bash
docker compose exec web python manage.py shell -c "from apps.recon.models import Program,ScopeAsset; p,_=Program.objects.get_or_create(slug='capital-com',defaults={'name':'Capital.com'}); ScopeAsset.objects.get_or_create(program=p,asset_type='wildcard',value='*.capital.com',in_scope=True); ScopeAsset.objects.get_or_create(program=p,asset_type='wildcard',value='*.backend-capital.com',in_scope=True)"
```

## Modulo 1 (Recon): subfinder + dnsx + persistencia de hosts vivos

```bash
docker compose exec web python manage.py run_recon_module1 --program capital-com --authorized-token I_HAVE_PERMISSION
```

Observacao: uso exclusivo em alvos autorizados por escopo de bug bounty.
