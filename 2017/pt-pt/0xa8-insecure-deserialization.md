# A8:2017 De-serialização Insegura

| Agentes de Ameaça/Vectores de Ataque | Fraquezas de Segurança           | Impactos               |
| -- | -- | -- |
| Nível de Acesso \| Exploração 1 | Prevalência 2 \| Deteção 2 | Técnico 3 \| Negócio |
| A exploração da de-serialização é algo difícil, uma vez que os exploits existentes ("off the shelft") raramente funcionam sem alterações ou modificações ao código do exploit subjacente. | Este assunto está incluido no Top 10 baseado numa [pesquisa de indústria](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) e não baseado em dados quantificávis. Algumas ferramentas podem descobrir falhas de de-serialização, no entanto, a assistência humana é frequentemente necessária para validar o problema. It is expected that prevalence data for deserialization flaws will increase as tooling is developed to help identify and address it. | The impact of deserialization flaws cannot be understated. They can lead to remote code execution attacks, one of the most serious attacks possible. |

## Está a Aplicação Vulnerável?

Distributed applications or those that need to store state on clients or the filesystem may be using object serialization. Distributed applications with public listeners or applications that rely on the client maintaining state, are likely to allow for tampering of serialized data. This attack can be possible regardless of the serialization format (binary or text) or the programming language.  Applications and APIs will be vulnerable if the when:
* The serialization mechanism allows for the creation of arbitrary data types, AND
* There are classes available to the application that can be chained together to change application behavior during or after deserialization, or unintended content can be used to influence application behavior, AND
* The application or API accepts and deserializes hostile objects supplied by an attacker, or an application uses serialized opaque client side state without appropriate tamper resistant controls. OR
* Security state sent to an untrusted client without some form of integrity control is likely vulnerable to deserialization.

## Como Prevenir?

The only safe architectural pattern is to not accept serialized objects from untrusted sources or to use serialization mediums that only permit primitive data types.

If that is not possible:
* Implement integrity checks or encryption of the serialized objects to prevent hostile object creation or data tampering.
* Enforce strict type constraints during deserialization before object creation; typically code is expecting a definable set of classes. Bypasses to this technique have been demonstrated.
* Isolate code that deserializes, such that it runs in very low privilege environments.
* Log deserialization exceptions and failures, such as where the incoming type is not the expected type, or the deserialization throws exceptions.
* Restrict or monitor incoming and outgoing network connectivity from containers or servers that deserialize.
* Monitor deserialization, alerting if a user deserializes constantly.

## Exemplos de Cenários de Ataque

**Cenário #1**: A React app calls a set of Spring Boot microservices. Being functional programmers, they tried to ensure that their code is immutable. The solution they came up with is serializing user state and passing it back and forth with each request. An attacker notices the "R00" Java object signature, and uses the Java Serial Killer tool to gain remote code execution on the application server.

**Cenário #2**: A PHP forum uses PHP object serialization to save a "super" cookie, containing the user's user ID, role, password hash, and other state:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

An attacker changes the serialized object to give themselves admin privileges:

`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## Referências

### OWASP

* [OWASP Cheat Sheet: Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [OWASP Proactive Controls: Validate All Inputs](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard: TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### Externas

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* https://github.com/mbechler/marshalsec