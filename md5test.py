from Crypto.Hash import MD5, SHA1

h = MD5.new()

names = ['ENSEA', 'eNSEA', 'eNSeA', 'EN5EA']

print("Printing MD5 hashes:")
for i in names:
    h2 = MD5.new()
    h2.update(i.encode('utf-8'))
    print("Printing MD5 of " + i + ": " + h2.hexdigest())

print("Printing SHA1 hashes:")
for i in names:
    h2 = SHA1.new()
    h2.update(i.encode('utf-8'))
    print("Printing SHA1 of " + i + ": " + h2.hexdigest())

print('test bs text: ')
h3 = MD5.new()
h3.update("""No mundo atual, a análise aprofundada dos indicadores-chave desafia a capacidade de equalização da articulação interinstitucional necessária. Com efeito, a competitividade nas transações comerciais ancora-se em pressupostos teóricos consistentes de todos os recursos funcionais envolvidos. Acima de tudo, é fundamental ressaltar que a valorização de fatores subjetivos causa impacto indireto na reavaliação das formas de ação.Por intermédio de análises qualificadas, a percepção das dificuldades ressalta a relevância da participação ativa do investimento em reciclagem técnica. É claro que a articulação entre os diferentes níveis institucionais exige a precisão e a definição do levantamento das variáveis envolvidas. Todavia, o desafiador cenário globalizado instiga a construção de consensos estratégicos das diversas correntes de pensamento. Desta maneira, o consenso sobre a necessidade de qualificação ainda não demonstrou convincentemente que vai participar na mudança dos métodos utilizados na avaliação de resultados. Ainda assim, existem dúvidas a respeito de como a adoção de políticas descentralizadoras modifica os parâmetros tradicionais de análise das diretrizes de desenvolvimento para o futuro.Por conseguinte, a expansão dos mercados mundiais nos obriga à análise dos relacionamentos verticais entre as hierarquias. Percebemos, cada vez mais, que o fenômeno da Internet eleva o grau de responsabilidade compartilhada das interfaces entre as dimensões técnico-políticas. As experiências acumuladas demonstram que o julgamento imparcial das eventualidades maximiza as possibilidades por conta dos aprendizados oriundos da experiência acumulada. Em função das demandas emergentes, o entendimento das metas propostas possibilita uma melhor visão global das direções preferenciais no sentido do progresso.Do ponto de vista estrutural, a reestruturação das práticas organizacionais deve passar por modificações independentemente dos princípios que regem a boa governança. Vale destacar que a dinamização das capacidades institucionais faz parte de um processo de gerenciamento do processo de comunicação como um todo. Neste sentido, a transição para modelos mais colaborativos é uma das consequências das dinâmicas sociais em transformação. À medida que avançamos, a incorporação de perspectivas multidisciplinares apresenta tendências no sentido de aprovar a manutenção das variáveis críticas de sucesso organizacional.""".encode('utf-8'))
print("Printing MD5 of test bs text: " + h3.hexdigest())


