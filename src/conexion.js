const sqlite3 = require('sqlite3').verbose()
const md5 = require('md5')

//Ruta donde se encuentra la Base de Datos.
const DBSOURCE = "./Alimentacion.db"

//Establecemos la conexion.
let db = new sqlite3.Database(DBSOURCE, (err) => {
    if (err) {
      // Mensaje que indica error en la conexion (Cannot open database).
      console.error(err.message)
      throw err
    }else{
      //Mensaje que indica que la conexion fue exitosa.
        console.log('Connected to the SQLite database.')

    }
});


module.exports = db
