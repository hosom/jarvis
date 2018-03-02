import cbapi

from errbot import BotPlugin, arg_botcmd

class CbResponse(BotPlugin):
	'''Carbon Black Response Integration
	'''

	def activate(self):
		'''
		Triggers on plugin activation
		'''
		super(CbResponse, self).activate()

		self.cb = cbapi.response.CbResponseAPI()

	@arg_botcmd('search_string', type=str, template='sensor_search')
	def cb_sensor_search(self, message, search_string=None):
		'''Search sensors within Carbon Black Response
		'''
		try:
			results = self.cb.select(cbapi.response.Sensor).where(search_string)
		except ValueError:
			return dict(err=True)
		sensors = [result for result in results]

		return dict(sensors=sensors)

	@arg_botcmd('sensor_id', type=int, template='sensor_print')
	def cb_sensor_print(self, message, sensor_id=None):
		'''Print information about a Carbon Black sensor using its sensor id.
		'''
		sensor = self.cb.select(cbapi.response.Sensor, sensor_id)
		sensor.refresh()
		return dict(sensor=sensor)

	@arg_botcmd('sensor_id', type=int, template='sensor_isolate')
	def cb_sensor_isolate(self, message, sensor_id=None):
		'''Isolate a sensor using the sensor's Carbon Black sensor id.
		'''
		sensor = self.cb.select(cbapi.response.Sensor, sensor_id)
		try:
			sensor.isolate(timeout=1)
		except:
			pass
		return dict(sensor=sensor)

	@arg_botcmd('sensor_id', type=int, template='sensor_unisolate')
	def cb_sensor_unisolate(self, message, sensor_id=None):
		'''Remove isolation from a sensor using the sensor's Carbon Black sensor id.
		'''
		sensor = self.cb.select(cbapi.response.Sensor, sensor_id)
		try:
			sensor.unisolate(timeout=1)
		except:
			pass
		return dict(sensor=sensor)