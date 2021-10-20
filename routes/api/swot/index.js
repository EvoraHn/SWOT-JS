var express = require('express');
var router = express.Router();
var SwotDao = require('./swot.dao');
var Swot = new SwotDao();

router.get('/all', async (req, res, next)=>{
  try{
    const allSwotEntries = await Swot.getAll();
    return res.status(200).json(allSwotEntries);
  }catch(ex){
    console.log(ex);
    return res.status(500).json({msg:"Error al procesar petición"});
  }
});

router.get('/byid/:id', async (req, res, next)=>{
  try {
    const {id} = req.params;
    const oneSwotEntry = await Swot.getById(id);
    return res.status(200).json(oneSwotEntry);
  } catch (ex) {
    console.log(ex);
    return res.status(500).json({ msg: "Error al procesar petición" });
  }
}); // byid

router.get('/bytype/:type', async (req, res, next)=>{
  try {
    const {type} = req.params;
    const swots = await Swot.getByType(type);
    return res.status(200).json(swots);
  } catch(ex){
    console.log(ex);
    return res.status(500).json({ msg: "Error al procesar petición" });
  }
}); // get by type

router.get('/bymeta/:meta', async (req, res, next) => {
  try {
    const { meta } = req.params;
    const swots = await Swot.getByMetaKey(meta);
    return res.status(200).json(swots);
  } catch (ex) {
    console.log(ex);
    return res.status(500).json({ msg: "Error al procesar petición" });
  }
}); // get by meta

router.post('/new', async (req, res, next)=>{
  try{
    const {
      swotType,
      swotDesc,
      swotMeta
    } = req.body;
    const swotMetaArray = swotMeta.split('|');
    // validaciones
    const result = await Swot.addNew(swotType, swotDesc, swotMetaArray);
    console.log(result);
    res.status(200).json({msg:"Agregado Satisfactoriamente"});
  } catch (ex) {
    console.log(ex);
    return res.status(500).json({ msg: "Error al procesar petición" });
  }
}); // /new

/*
// Uso tradicional con inyeccion de handlers | funciones
router.get('/all', (req, res, next) => {
    Swot.getAll((err, allSwotEntries)=>{
      if(err){
        return res.status(500).json({ msg: "Error al procesar petición" });
      }
      return res.status(200).json(allSwotEntries);
    });
});
*/
// SWOT = FODA = Strength, Weakness, Oportunity, Threats
// Fortalezas, Oportunidades, Debilidades, Amenazas

router.put('/update/:id', async (req, res, next)=>{
  try {
    const {id} = req.params;
    const {swotMetaKey} = req.body;
    const result = await Swot.addMetaToSwot(swotMetaKey, id);
    console.log(result);
    res.status(200).json({"msg":"Modificado OK"});
  } catch (ex){
    console.log(ex);
    return res.status(500).json({ msg: "Error al procesar petición" });
  }
}); // put update

router.delete('/delete/:id', async (req, res, next)=>{
  try {
    const {id} = req.params;
    const result = await Swot.deleteById(id);
    console.log(result);
    return res.status(200).json({"msg":"Eliminado OK"});
  } catch (ex) {
    console.log(ex);
    return res.status(500).json({ msg: "Error al procesar petición" });
  }
}); // delete

module.exports = router;
