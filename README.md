# Projeto em Teoria da Computação (MC856)

![Capa do Projeto](https://github.com/I3run0/mc856/blob/main/graph_analysis/images/grafo.png)

Este projeto foi desenvolvido no contexto da disciplina MC856 - Projeto em Teoria da Computação. Cada aluno propôs uma ideia de projeto envolvendo grafos, e este, em particular, visa analisar as relações de dependência entre pacotes no ecossistema PyPI. O objetivo central é compreender como vulnerabilidades em determinados pacotes podem se propagar pela rede de dependências desse repositório, impactando outros pacotes e aumentando os riscos para desenvolvedores e aplicações que utilizam essas bibliotecas.

Por meio da análise das conexões e da propagação de vulnerabilidades na rede de dependências, o projeto busca fornecer insights sobre a robustez do ecossistema, identificar pacotes críticos e vulneráveis e entender quais pacotes podem ser mais suscetíveis a ataques de cadeia de suprimentos.

## Estrutura do Repositório

Este repositório dispara um job do GitHub para executar o script dentro da pasta `pypi-data-downloader`, de modo que ele baixe os metadados dos pacotes do PyPI a cada intervalo de tempo, mantendo os dados disponíveis na pasta `release_data` sempre atualizados para análise. Esse diretório contém apenas metadados dos pacotes em formato JSON, para futuro consumo e construção de um dataset menor. Isso foi feito porque o PyPI não oferece todos os metadados dos pacotes de uma só vez, algo importante para montar o grafo de dependências como um todo.

Além disso, scripts para construção de um dataset com dados filtrados para a tarefa proposta, assim como o script para a construção do próprio grafo de dependências e outro para calcular métricas sobre esses grafos, estão presentes no diretório `graph_analysis`. Dentro deste diretório também existe um notebook com algumas métricas já caluladas.
