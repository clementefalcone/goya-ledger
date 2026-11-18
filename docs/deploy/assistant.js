export const ROLES = {
  pyme: { label: "Tengo una pyme", example: "una cotización o un contrato con un cliente" },
  independiente: { label: "Trabajo independiente", example: "un contrato de servicios" },
  arriendos: { label: "Arriendo o administro propiedades", example: "un contrato de arriendo" },
  personas: { label: "Veo personas o RRHH", example: "un contrato de trabajo o un finiquito" },
};

const PAIN_OPTIONS = [
  { label: "Alguien dijo que acordamos otra cosa", go: "disputa" },
  { label: "Me llegó un documento que parecía falso", go: "falso" },
  { label: "Pierdo tiempo comprobando documentos", go: "verificar" },
  { label: "Firmar con otros es lento", go: "firmar" },
  { label: "Ninguna, solo quiero entender", go: "que" },
];

const QUESTION_OPTIONS = [
  { label: "¿Qué es Goya, en simple?", go: "que" },
  { label: "¿Tengo que saber de tecnología?", go: "tecnologia" },
  { label: "¿Qué pasa si no hago nada?", go: "nada" },
  { label: "¿Esto es blockchain o cripto?", go: "blockchain" },
  { label: "¿Me afectan los computadores cuánticos?", go: "cuantico" },
];

const AFTER_ANSWER_OPTIONS = [
  { label: "Me pasa otra cosa", go: "dolores" },
  ...QUESTION_OPTIONS,
];

export const STEPS = {
  inicio: {
    say: () => [
      "Hola. Soy el asistente de Goya.",
      "En dos minutos te digo si esto te sirve o no. Sin tecnicismos y sin nada que instalar. ¿A qué te dedicas?",
    ],
    options: () => Object.entries(ROLES).map(([role, { label }]) => ({ label, go: "dolores", role })),
  },
  dolores: {
    say: () => ["¿Te ha pasado alguna de estas cosas?"],
    options: () => PAIN_OPTIONS,
  },
  disputa: {
    say: ({ example }) => [
      `Pasa más de lo que crees: tú tienes una versión de ${example}, la otra persona tiene otra, y es tu palabra contra la suya.`,
      "Con Goya, el documento queda sellado con su fecha y con una huella única. Si mañana aparece otra versión, aunque cambie una sola coma, la diferencia salta a la vista. Nadie tiene que discutir quién tiene razón.",
      "Tú sigues trabajando igual, con tus PDF y tu Excel.",
    ],
    options: () => AFTER_ANSWER_OPTIONS,
  },
  falso: {
    say: () => [
      "Editar un PDF toma segundos y a simple vista no se nota.",
      "Cuando quien emite un documento lo sella con Goya, tú compruebas en un segundo si es el original: coincide o no coincide.",
      "Te lo digo con honestidad: solo funciona si quien te envía el documento lo selló con Goya. Si no, Goya no puede decirte si es auténtico.",
    ],
    options: () => AFTER_ANSWER_OPTIONS,
  },
  verificar: {
    say: () => [
      "Llamar, pedir originales, esperar que alguien conteste: eso es tiempo y plata.",
      "Con un documento sellado, la comprobación toma un segundo y no depende de que nadie te responda, ni siquiera de que quien lo emitió siga existiendo.",
      "Igual que antes: funciona con documentos que su emisor selló con Goya.",
    ],
    options: () => AFTER_ANSWER_OPTIONS,
  },
  firmar: {
    say: ({ example }) => [
      `Hoy firmar ${example} con otra persona suele significar imprimir, escanear o ir a una notaría.`,
      "Con Goya, la otra persona firma desde un enlace en su celular, con firma electrónica simple (Ley 19.799). Queda registrado quién firmó, cuándo y qué versión exacta.",
      "Ojo: para algunos trámites la ley exige firma avanzada o notario. Esa todavía no la ofrecemos.",
    ],
    options: () => AFTER_ANSWER_OPTIONS,
  },
  que: {
    say: () => [
      "Goya es un sello para documentos digitales.",
      "Le pones el sello a un contrato, una cotización o un certificado, y después cualquiera puede comprobar que es exactamente el mismo, quién lo firmó y cuándo.",
      "Es como el timbre de una notaría, pero se comprueba en un segundo y desde cualquier parte.",
    ],
    options: () => AFTER_ANSWER_OPTIONS,
  },
  tecnologia: {
    say: () => [
      "No. Igual que no necesitas saber cómo funciona un banco para hacer una transferencia.",
      "Lo técnico queda por debajo. Tú solo ves tu documento, su sello y si coincide o no.",
    ],
    options: () => AFTER_ANSWER_OPTIONS,
  },
  nada: {
    say: () => [
      "Probablemente nada grave mañana.",
      "El problema aparece el día que tengas una discusión o te llegue un documento falso. Ahí vas a necesitar probar algo que hoy no estás guardando.",
      "Y hay un detalle importante: el sello se pone al momento de firmar. Después no se puede poner con la misma fuerza.",
    ],
    options: () => AFTER_ANSWER_OPTIONS,
  },
  blockchain: {
    say: () => [
      "No hay criptomonedas ni inversión de por medio.",
      "Por debajo, los sellos se guardan de forma que nadie, ni siquiera Goya, pueda cambiar una fecha sin que se note. Esa es la única parte de esa tecnología que usamos, y tú no la ves.",
    ],
    options: () => AFTER_ANSWER_OPTIONS,
  },
  cuantico: {
    say: () => [
      "A futuro, sí. Las firmas digitales de hoy se podrán falsificar cuando existan computadores cuánticos lo bastante grandes. Nadie sabe la fecha exacta.",
      "Si firmas cosas que deben valer por muchos años, como arriendos largos, poderes o finiquitos, conviene que ya usen sellos que resistan eso. Goya los usa.",
      "Puedes revisar si tus firmas actuales resisten en goyaledger.com/q-day.",
    ],
    options: () => AFTER_ANSWER_OPTIONS,
  },
};

export const DEFAULT_EXAMPLE = "un documento importante";

export function resolveStep(stepId, state) {
  const step = STEPS[stepId];
  if (!step) throw new Error(`Assistant step "${stepId}" does not exist`);
  return { messages: step.say(state), options: step.options(state) };
}

export function applyChoice(state, option) {
  if (!option.role) return state;
  return { ...state, role: option.role, example: ROLES[option.role].example };
}
